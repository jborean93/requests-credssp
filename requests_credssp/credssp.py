import base64
import binascii
import logging
import re
import struct

from ntlm_auth.ntlm import Ntlm
from requests.auth import AuthBase

from requests_credssp.asn_structures import TSCredentials, TSRequest, \
    TSPasswordCreds, NegoData
from requests_credssp.exceptions import AuthenticationException, \
    InvalidConfigurationException

HAS_KERBEROS = True
try:  # pragma: no cover
    import gssapi
    from gssapi.raw import acquire_cred_with_password  # needed for gssapi auth
except ImportError as exc:
    KERBEROS_IMPORT_ERROR = str(exc)
    HAS_KERBEROS = False
    pass

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

try:
    from OpenSSL import SSL, _util
except ImportError:  # pragma: no cover
    try:
        from OpenSSL import SSL
        from OpenSSL import crypto as _util
    except ImportError:
        raise Exception("Cannot import pyOpenSSL")

log = logging.getLogger(__name__)


class HttpCredSSPAuth(AuthBase):

    BIO_BUFFER_SIZE = 8192

    def __init__(self, username, password, auth_mechanism='auto',
                 disable_tlsv1_2=False):
        """
        Initialises the CredSSP auth handler for dealing with requests.

        :param username: The username including domain to auth with
            (DOMAIN\\USER or USER@DOMAIN.LOCAL)
        :param password: The password for the user above to delegate to the
            server
        :param auth_mechanism: The authentication mechanism
            auto, ntlm, kerberos
        :param disable_tlsv1_2: Disable TLSv1.2 authentication and revert back
            to TLSv1.
        """
        self.username = username
        self.password = password

        if auth_mechanism == 'auto' and HAS_KERBEROS:
            self.contexts = [GSSApiContext, NTLMContext]
        elif auth_mechanism == 'auto' or auth_mechanism == 'ntlm':
            self.contexts = [NTLMContext]
        elif auth_mechanism == 'kerberos' and HAS_KERBEROS:
            self.contexts = [GSSApiContext]
        elif auth_mechanism == 'kerberos':
            raise InvalidConfigurationException("Auth mechnism kerberos is "
                                                "chosen but python-gssapi is "
                                                "not installed: %s"
                                                % KERBEROS_IMPORT_ERROR)
        else:
            raise InvalidConfigurationException("Unknown auth mechanism %s, "
                                                "valid options are auto, "
                                                "ntlm, or kerberos"
                                                % auth_mechanism)

        if disable_tlsv1_2:
            """
            Windows 7 and Server 2008 R2 uses TLSv1 by default which is
            considered insecure. Microsoft have released a KB that adds support
            for TLSv1.2 https://support.microsoft.com/en-us/kb/3080079 which
            can be installed. Once installed the relevant reg keys need to be
            configured as show by this page
            https://technet.microsoft.com/en-us/library/dn786418.aspx

            If you do not wish to do this you can set the disable_tlsv1_2 flag
            to true when calling CredSSP (NOT RECOMMENDED).
            """
            log.debug("disable_tlsv1_2 is set to False, disabling TLSv1.2"
                      "support and reverting back to TLSv1")
            self.tls_context = SSL.Context(SSL.TLSv1_METHOD)

            # Revert OpenSSL fix to CBC ciphers due to incompatibility with
            # MS TLS 1.0 implementation SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
            # 0x00000800 - SSL_OP_TLS_BLOCK_PADDING_BUG 0x00000200
            self.tls_context.set_options(0x00000800 | 0x00000200)
        else:
            self.tls_context = SSL.Context(SSL.TLSv1_2_METHOD)

        self.tls_context.set_cipher_list(b'ALL')
        self.tls_connection = None

        # used when calculating the trailer length for WinRM
        self.cipher_negotiated = None

    def __call__(self, request):
        request.headers["Connection"] = "Keep-Alive"
        request.register_hook('response', self.response_hook)

        return request

    def response_hook(self, response, **kwargs):
        if response.status_code == 401:
            response.content
            response.raw.release_conn()
            response = self.retry_with_credssp(response, **kwargs)

        return response

    def retry_with_credssp(self, response, **kwargs):
        """
        [MS-CSSP] v13.0 2016-07-14

        3.1.5 Processing Events and Sequencing Rules
        The CredSSP Protocol is carried out in the following sequence and is
        subject to the protocol rules that are described in the following steps

        :param response: The original 401 response when sending the first
            request to the server
        :param kwargs: The requests kwargs from the original response
        :return: The final response from the server after successful
            authentication, status code 200
        """
        log.info("Start TLS Handshake process")
        self._start_tls_handshake(response, **kwargs)

        log.info("Start authentication process")
        hostname = urlparse(response.url).hostname
        server_certificate = self.tls_connection.get_peer_certificate()
        server_public_key = self._get_rsa_public_key(server_certificate)

        auth_complete = False
        errors = []
        for context in self.contexts:
            # try all possible contexts for CredSSP authentication
            class_type = context.__name__
            log.debug("Trying %s authentication" % class_type)
            try:
                context = context(hostname, self.username, self.password)
                server_cert = self._authenticate(context, server_public_key,
                                                 response, **kwargs)
            except Exception as exc:
                # failed to authenticate with this auth context, keep on trying
                # the remaining ones
                log.warning("%s authentication failed: %s"
                            % (class_type, str(exc)))
                errors.append("%s: %s" % (class_type, exc))
            else:
                log.info("%s authentication successful" % class_type)
                auth_complete = True
                break

        if not auth_complete:
            raise AuthenticationException("Failed to authenticate with "
                                          "server: %s" % str(errors))

        log.info("Verify the server's public certificate to mitigate"
                 "MitM attacks")
        self._verify_public_keys(context, server_public_key, server_cert)

        log.info("Sending encrypted credentials to the server")
        final_response = self._send_encrypted_credentials(context, response,
                                                          **kwargs)
        final_response.history.append(response)
        log.info("Authentication complete")

        return final_response

    def _start_tls_handshake(self, response, **kwargs):
        """
        [MS-CSSP] v13.0 2016-07-14

        3.1.5 Processing Events and Sequencing Rules - Step 1
        This is the first step in a CredSSP auth sequence where the client and
        server complete the TLS handshake as specified in RFC2246. After the
        handshake is complete, all subsequent CredSSP Protocol messages are
        encrypted by the TLS channel.

        :param response: The original 401 response from the server
        :param kwargs: The requests kwargs from the original response
        """
        # Check that the server support CredSSP authentication
        self._check_credssp_supported(response)

        self.tls_connection = SSL.Connection(self.tls_context)
        self.tls_connection.set_connect_state()

        log.debug("_start_tls_handshake(): Starting TLS handshake with server")
        while True:
            try:
                self.tls_connection.do_handshake()
            except SSL.WantReadError:
                request = response.request.copy()
                credssp_token = \
                    self.tls_connection.bio_read(self.BIO_BUFFER_SIZE)
                self._set_credssp_token(request, credssp_token)

                response = response.connection.send(request, **kwargs)
                response.content
                response.raw.release_conn()

                server_credssp_token = self._get_credssp_token(response)
                self.tls_connection.bio_write(server_credssp_token)
            else:
                break

        self.cipher_negotiated = self.tls_connection.get_cipher_name()
        log.debug("_start_tls_handshake(): Handshake complete. Protocol: %s, "
                  "Cipher: %s"
                  % (self.tls_connection.get_protocol_version_name(),
                     self.tls_connection.get_cipher_name()))

    def _authenticate(self, context, server_public_cert, response, **kwargs):
        """
        [MS-CSSP] v13.0 2016-07-14

        3.1.5 Processing Events and Sequencing Rules - Step 2 and 3
        Over the encrypted TLS channel, the Kerberos or NTLM token is sent from
        the client to the server and complete the initial authentication
        context.

        Once a context is established, the client encrypts the public cert of
        the server using the auth context. This key is then sent to the server
        as part of the TSRequest.

        :param context: The authentication context class to use in
            authentication
        :param server_public_cert: The ASN.1 encoded SubjectPublicKey field of
            the server's X509 certificate
        :param response: The response from the server after completing the TLS
            handshake
        :param kwargs: The requests kwargs from the original response
        :return: The TSRequest structure received from the server containing
            the pubKeyAuth for the client to verify
        """
        for out_token in context.step():
            nego_data = NegoData()
            nego_data['nego_token'].value = out_token
            ts_request = TSRequest()
            ts_request['nego_tokens'].value = nego_data.get_data()

            credssp_token = self.wrap(ts_request.get_data())
            auth_request = response.request.copy()
            self._set_credssp_token(auth_request, credssp_token)

            log.info("_authenticate(): Sending authentication request")
            response = response.connection.send(auth_request, **kwargs)
            response.content
            response.raw.release_conn()
            response_token = self._get_credssp_token(response)
            response_token_data = self.unwrap(response_token)

            ts_request = TSRequest()
            ts_request.parse_data(response_token_data)
            ts_request.check_error_code()

            nego_data = NegoData()
            nego_data.parse_data(ts_request['nego_tokens'].value)
            context.in_token = nego_data['nego_token'].value

        # now send the final auth token with the server's public cert
        encrypted_public_key = context.wrap(server_public_cert)

        ts_request = TSRequest()
        ts_request['pub_key_auth'].value = encrypted_public_key

        if context.final_token is not None:
            auth_nego_data = NegoData()
            auth_nego_data['nego_token'].value = context.final_token
            ts_request['nego_tokens'].value = auth_nego_data.get_data()

        log.debug("_authenticate(): Send TSRequest structure containing the "
                  "final auth token and public key info")
        auth_credssp_token = self.wrap(ts_request.get_data())

        request = response.request.copy()
        self._set_credssp_token(request, auth_credssp_token)

        log.debug("_authenticate(): Get the public key structure response from"
                  " the server")
        response = response.connection.send(request, **kwargs)
        response.content
        response.raw.release_conn()
        public_key_credssp_token = self._get_credssp_token(response)
        public_key_requests_data = self.unwrap(public_key_credssp_token)

        public_key_ts_request = TSRequest()
        public_key_ts_request.parse_data(public_key_requests_data)
        public_key_ts_request.check_error_code()

        if public_key_ts_request['pub_key_auth'].value is None:
            raise AuthenticationException('The server did not respond with '
                                          'pubKeyAuth info auth was rejected')

        return public_key_ts_request

    def _verify_public_keys(self, context, expected_key,
                            public_key_ts_request):
        """
        [MS-CSSP] v13.0 2016-07-14

        3.1.5 Processing Events and Sequencing Rules - Step 4
        After the server received the public key in Step 3 it verifies the key
        with what was in the handshake. After the verification it then add 1 to
        the first byte representing the public key and encrypts the binary
        result by using the authentication protocol's encryption services.

        This method does the opposite where it will decrypt the public key
        returned from the server and subtract the first byte by 1 to compare
        with the public key we sent originally.

        :param expected_key: The ASN.1 encoded SubjectPublicKey field of the
            server X509 certificate
        :param public_key_ts_request: The TSRequest structure received from the
            server for host verification
        """
        log.debug("_verify_public_keys(): Get raw public key from the server "
                  "and decrypt it for verification")
        raw_public_key = public_key_ts_request['pub_key_auth'].value

        public_key = context.unwrap(raw_public_key)

        # Get the first byte from the server public key and subtract it by 1
        first_byte = struct.unpack("<B", public_key[0:1])[0]

        new_byte = struct.pack('<B', first_byte - 1)
        actual_key = new_byte + public_key[1:]

        if actual_key != expected_key:
            raise AuthenticationException("Could not verify key sent from the "
                                          "server, potential man in the middle"
                                          " attack")
        log.debug("_verify_public_keys(): verification of the server's public "
                  "key is successful")

    def _send_encrypted_credentials(self, context, response, **kwargs):
        """
        [MS-CSSP] v13.0 2016-07-14

        3.1.5 Processing Events and Sequencing Rules - Step 5
        After the client has verified the server's authenticity, it encrypts
        the user's credentials with the authentication protocol's encryption
        services. The resulting value is encapsulated in the authInfo field of
        the TSRequest structure and sent over the encrypted TLS channel to the
        server

        :param response: The response from the server after completing the TLS
            handshake
        :param kwargs: The requests kwargs from the original response
        :return: The final response from the server after successful
            authentication, status code 200
        """
        ts_password_credentials = TSPasswordCreds()
        ts_password_credentials['domain_name'].value = \
            context.domain.encode('utf-16-le')
        ts_password_credentials['user_name'].value = \
            context.username.encode('utf-16-le')
        ts_password_credentials['password'].value = \
            context.password.encode('utf-16-le')

        ts_credentials = TSCredentials()
        # TODO: Add support for different credential types
        ts_credentials['cred_type'].value = struct.pack('B', 1)
        ts_credentials['credentials'].value = \
            ts_password_credentials.get_data()

        credential_ts_request = TSRequest()
        encrypted_credential = context.wrap(ts_credentials.get_data())
        credential_ts_request['auth_info'].value = encrypted_credential

        credential_credssp_token = self.wrap(credential_ts_request.get_data())
        request = response.request.copy()
        self._set_credssp_token(request, credential_credssp_token)

        log.info("_send_encrypted_credentials(): Sending the encrypted "
                 "credentials to the server")
        response = response.connection.send(request, **kwargs)

        return response

    def wrap(self, data):
        """
        Encrypts the data in preparation for sending to the server. The data is
        encrypted using the TLS channel negotiated between the client and the
        server.

        :param data: a byte string of data to encrypt
        :return: a byte string of the encrypted data
        """
        length = self.tls_connection.send(data)
        encrypted_data = b''
        counter = 0

        while True:
            try:
                encrypted_chunk = \
                    self.tls_connection.bio_read(self.BIO_BUFFER_SIZE)
            except SSL.WantReadError:
                break
            encrypted_data += encrypted_chunk

            # in case of a borked TLS connection, break the loop if the current
            # buffer counter is > the length of the original message plus the
            # the size of the buffer (to be careful)
            counter += self.BIO_BUFFER_SIZE
            if counter > length + self.BIO_BUFFER_SIZE:
                break

        return encrypted_data

    def unwrap(self, encrypted_data):
        """
        Decrypts the data send by the server using the TLS channel negotiated
        between the client and the server.

        :param encrypted_data: the byte string of the encrypted data
        :return: a byte string of the decrypted data
        """
        length = self.tls_connection.bio_write(encrypted_data)
        data = b''
        counter = 0

        while True:
            try:
                data_chunk = self.tls_connection.recv(self.BIO_BUFFER_SIZE)
            except SSL.WantReadError:
                break
            data += data_chunk

            counter += self.BIO_BUFFER_SIZE
            if counter > length:
                break

        return data

    @staticmethod
    def _check_credssp_supported(response):
        authenticate_header = response.headers.get('www-authenticate', '')
        if 'CREDSSP' not in authenticate_header.upper():
            raise AuthenticationException('The server did not respond with a '
                                          'CredSSP as an available auth '
                                          'method')

    @staticmethod
    def _get_credssp_token(response):
        authenticate_header = response.headers.get('www-authenticate', '')
        token_regex = re.compile('CredSSP ([^,\s]*)$', re.I)
        token_match = token_regex.search(authenticate_header)

        if token_match:
            encoded_token = token_match.group(1)
            decoded_token = base64.b64decode(encoded_token)
            return decoded_token
        else:
            raise AuthenticationException("The server did not response with a "
                                          "CredSSP token, auth rejected")

    @staticmethod
    def _set_credssp_token(request, token):
        encoded_token = base64.b64encode(token)
        credssp_header = "CredSSP ".encode() + encoded_token
        request.headers['Authorization'] = credssp_header

    @staticmethod
    def _get_rsa_public_key(cert):
        """
        Written by Ian Clegg
        github.com/ianclegg/winrmlib/blob/master/winrmlib/api/authentication.py

        PyOpenSSL does not provide a public method to export the public key
        from a certificate as a properly formatted ASN.1 RSAPublicKey
        structure. There are 'hacks' which use
        dump_privatekey(crypto.FILETYPE_ASN1, <public_key>), but this dumps the
        public key within a PrivateKeyInfo structure which is not suitable for
        a comparison. This approach uses the PyOpenSSL CFFI bindings to invoke
        the i2d_RSAPublicKey() which correctly extracts the key material in an
        ASN.1 RSAPublicKey structure.

        :param cert: The ASN.1 Encoded Certificate
        :return: The ASN.1 Encoded RSAPublicKey structure containing the
            supplied certificates public Key
        """
        openssl_pkey = cert.get_pubkey()
        openssl_lib = _util.binding.lib
        ffi = _util.binding.ffi
        buf = ffi.new("unsigned char **")
        rsa = openssl_lib.EVP_PKEY_get1_RSA(openssl_pkey._pkey)
        length = openssl_lib.i2d_RSAPublicKey(rsa, buf)
        public_key = ffi.buffer(buf[0], length)[:]
        ffi.gc(buf[0], openssl_lib.OPENSSL_free)

        return public_key


class NTLMContext(object):

    def __init__(self, hostname, username, password):
        # try and get the domain part from the username
        log.info("Setting up NTLM Security Context for user %s" % username)
        try:
            self.domain, self.username = username.split("\\", 1)
        except ValueError:
            self.username = username
            self.domain = ''
        self.password = password
        self.in_token = None
        self.final_token = None

        self._context = Ntlm()

    def step(self):
        msg1 = self._context.create_negotiate_message(self.domain)
        msg1 = base64.b64decode(msg1)

        log.debug("NTLM Negotiate message: %s" % binascii.hexlify(msg1))
        yield msg1

        log.info("NTLM: Parsing Challenge message: %s" % self.in_token)
        msg2 = base64.b64encode(self.in_token)
        self._context.parse_challenge_message(msg2)

        log.info("NTLM: Generating Authenticate message")
        msg3 = self._context.create_authenticate_message(
            user_name=self.username,
            password=self.password,
            domain_name=self.domain
        )
        self.final_token = base64.b64decode(msg3)

    def wrap(self, data):
        enc_data, enc_signature = self._context.session_security.wrap(data)
        return enc_signature + enc_data

    def unwrap(self, data):
        return self._context.session_security.unwrap(data[16:], data[:16])


class GSSApiContext(object):

    def __init__(self, hostname, username, password):
        log.info("Setting up GSSAPI Security Context for user %s" % username)
        self.domain = ''
        self.username = username
        self.password = password
        self.in_token = None
        self.final_token = None

        server_name = gssapi.Name('http@%s' % hostname,
                                  name_type=gssapi.NameType.hostbased_service)
        cred = self._get_kerberos_credential(self.username, self.password)
        self._context = gssapi.SecurityContext(name=server_name, creds=cred,
                                               usage='initiate')

    def step(self):
        while not self._context.complete:
            log.info("GSSAPI: gss_init_sec_context called")
            out_token = self._context.step(self.in_token)
            if out_token:
                yield out_token
            else:
                log.info("GSSAPI: gss_init_sec_context complete")

    def wrap(self, data):
        return self._context.wrap(data, True)[0]

    def unwrap(self, data):
        return self._context.unwrap(data)[0]

    def _get_kerberos_credential(self, username, password):
        log.debug("GSSAPI: Acquiring credentials handle for user %s with "
                  "password" % username)

        user = gssapi.Name(base=username,
                           name_type=gssapi.NameType.user)
        bpass = password.encode('utf-8')
        try:
            creds = acquire_cred_with_password(user, bpass, usage='initiate')
        except gssapi.exceptions.GSSError as er:
            raise AuthenticationException("Failed to acquire GSSAPI "
                                          "credential with password: %s"
                                          % str(er))

        log.info("GSSAPI: Acquired credentials for user %s" % str(user))
        return creds.creds
