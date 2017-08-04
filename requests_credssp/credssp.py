import base64
import logging
import re
import struct

try:
    from OpenSSL import SSL, _util
except ImportError:
    try:
        from OpenSSL import SSL
        from OpenSSL import crypto as _util
    except ImportError:
        raise Exception("Cannot import pyOpenSSL")
from ntlm_auth.ntlm import Ntlm
from requests.auth import AuthBase

from requests_credssp.asn_structures import TSCredentials, TSRequest, TSPasswordCreds, NegoData
from requests_credssp.exceptions import AuthenticationException, InvalidConfigurationException

log = logging.getLogger(__name__)

class HttpCredSSPAuth(AuthBase):

    BIO_BUFFER_SIZE = 8192

    def __init__(self, username, password, auth_mechanism='ntlm', disable_tlsv1_2=False):
        """
        Initialises the CredSSP auth handler for dealing with requests.

        :param username: The username including domain to auth with (DOMAIN\\USER or USER@DOMAIN.LOCAL)
        :param password: The password for the user above to delegate to the server
        :param auth_mechanism: The authentication mechanism (ntlm, kerberos) - Only NTLM is implemented so far
        :param disable_tlsv1_2: Disable TLSv1.2 authentication and revert back to TLSv1.
        """
        self.domain, self.user = self._parse_username(username)
        log.debug("The credentials that will be used in the auth, DOMAIN: '%s', USER: '%s'" % (self.domain, self.user))
        self.password = password

        if auth_mechanism == 'ntlm':
            self.context = Ntlm()
        elif auth_mechanism == 'kerberos':
            raise InvalidConfigurationException('Kerberos auth not yet implemented, please use NTLM instead')
        else:
            raise InvalidConfigurationException('Unknown auth mechanism %s, please specify ntlm' % auth_mechanism)

        if disable_tlsv1_2 == True:
            """
            Windows 7 and Server 2008 R2 uses TLSv1 by default which is considered insecure. Microsoft have released
            a KB that adds support for TLSv1.2 https://support.microsoft.com/en-us/kb/3080079 which can be installed.
            Once installed the relevant entry keys need to be configured as show by this page
            https://technet.microsoft.com/en-us/library/dn786418.aspx#BKMK_SchannelTR_TLS12.

            If you do not wish to do this you can set the disable_tlsv1_2 flag to true when calling CredSSP (NOT
            RECOMMENDED).
            """
            log.debug("disable_tlsv1_2 is set to False, disabling TLSv1.2 support and reverting back to TLSv1")
            self.tls_context = SSL.Context(SSL.TLSv1_METHOD)

            # Revert OpenSSL fix to CBC ciphers due to incompatibility with MS TLS 1.0 implementation
            # SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS 0x00000800 - SSL_OP_TLS_BLOCK_PADDING_BUG 0x00000200
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
        The CredSSP Protocol is carried out in the following sequence and is subject to the protocol rules that
        are described in the following steps

        :param response: The original 401 response when sending the first request to the server
        :param kwargs: The requests kwargs from the original response
        :return: The final response from the server after successful authentication, status code 200
        """
        # 1. Complete TLS Handshake
        self._start_tls_handshake(response, **kwargs)

        # 2. Creates the authentication token to send to the server in conjunction with Step 3
        server_certificate = self.tls_connection.get_peer_certificate()
        authenticate_token = self._get_authentication_token(response, server_certificate, **kwargs)

        # 3. Encrypt the public key and send in conjunction with the authentication token to the server
        server_public_key = self._get_rsa_public_key(server_certificate)
        public_key_ts_request = self._send_auth_response(response, authenticate_token, server_public_key, **kwargs)

        # 4. Verify server's public key response to thwart man in the middle attacks
        self._verify_public_keys(server_public_key, public_key_ts_request)

        # 5. Send encrypted credentials to the server
        final_response = self._send_encrypted_credentials(response, **kwargs)
        final_response.history.append(response)

        return final_response

    def _start_tls_handshake(self, response, **kwargs):
        """
        [MS-CSSP] v13.0 2016-07-14

        3.1.5 Processing Events and Sequencing Rules - Step 1
        This is the first step in a CredSSP auth sequence where the client and server complete the TLS handshake as
        specified in RFC2246. After the handshake is complete, all subsequent CredSSP Protocol messages are encrypted
        by the TLS channel.

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
                credssp_token = self.tls_connection.bio_read(self.BIO_BUFFER_SIZE)
                self._set_credssp_token(request, credssp_token)

                response = response.connection.send(request, **kwargs)
                response.content
                response.raw.release_conn()

                server_credssp_token = self._get_credssp_token(response)
                self.tls_connection.bio_write(server_credssp_token)
            else:
                break

        self.cipher_negotiated = self.tls_connection.get_cipher_name()
        log.debug("_start_tls_handshake(): Handshake complete. Protocol: %s, Cipher: %s" % (
                self.tls_connection.get_protocol_version_name(), self.tls_connection.get_cipher_name()))

    def _get_authentication_token(self, response, server_certificate, **kwargs):
        """
        [MS-CSSP] v13.0 2016-07-14

        3.1.5 Processing Events and Sequencing Rules - Step 2
        Over the encrypted TLS channel, the SPNEGO, Kerberos, or NTLM handshake between the client and server completes
        authentication and establishes an encryption key. While this step has us sending the final token to the
        server, this is done in conjunction with the public key done in Step 3

        :param response: The response from the server after completing the TLS handshake
        :param server_certificate: The certificate of the server endpoint to be used for Channel Binding Tokens
        :param kwargs: The requests kwargs from the original response
        :return: The final authentication token to be sent to the server
        """

        # TODO: Add support for Kerberos authentication and not just NTLM

        log.debug("_get_authentication_token(): creating NTLM negotiate token and add it to the initial TSRequest")
        negotiate_token = self.context.create_negotiate_message(self.domain).decode('ascii')
        log.debug("_get_authentication_token(): NTLM Negotiate Token: %s" % negotiate_token)
        negotiate_token = base64.b64decode(negotiate_token)

        negotiate_nego_data = NegoData()
        negotiate_nego_data['nego_token'].value = negotiate_token
        negotiate_ts_request = TSRequest()
        negotiate_ts_request['nego_tokens'].value = negotiate_nego_data.get_data()

        negotiate_credssp_token = self.wrap(negotiate_ts_request.get_data())
        negotiate_request = response.request.copy()
        self._set_credssp_token(negotiate_request, negotiate_credssp_token)

        log.debug("_get_authentication_token(): get NTLM challenge token from the "
                  "server and add it to the ntlm context")
        challenge_response = response.connection.send(negotiate_request, **kwargs)
        challenge_response.content
        challenge_response.raw.release_conn()
        challenge_credssp_token = self._get_credssp_token(challenge_response)
        challenge_ts_request_data = self.unwrap(challenge_credssp_token)

        challenge_ts_request = TSRequest()
        challenge_ts_request.parse_data(challenge_ts_request_data)
        challenge_ts_request.check_error_code()

        challenge_nego_data = NegoData()
        challenge_nego_data.parse_data(challenge_ts_request['nego_tokens'].value)
        challenge_token = challenge_nego_data['nego_token'].value
        encoded_challenge_token = base64.b64encode(challenge_token)
        log.debug("_get_authentication_token(): NTLM Challenge Token: %s" % encoded_challenge_token)
        self.context.parse_challenge_message(encoded_challenge_token)

        log.debug("_get_authentication_token(): create NTLM authentication token")
        server_cert_hash = server_certificate.digest('SHA256').decode().replace(':', '')
        authenticate_token = self.context.create_authenticate_message(self.user, self.password, self.domain,
                                                                      server_certificate_hash=server_cert_hash)
        authenticate_token = base64.b64decode(authenticate_token)

        return authenticate_token

    def _send_auth_response(self, response, authenticate_token, server_public_key, **kwargs):
        """
        [MS-CSSP] v13.0 2016-07-14

        3.1.5 Processing Events and Sequencing Rules - Step 3
        The client encrypts the public key it received from the server by using the confidentiality support of the
        authentication protocol (Kerberos/NTLM). This key is added to the pubKeyAuth field of the TSRequest along with
        the authenticate_token in the negoTokens field.

        :param response: The response from the server after completing the TLS handshake
        :param authenticate_token: The final authentication token to be sent to the server
        :param server_public_key: The ASN.1 encoded SubjectPublicKey field of the server X509 certificate
        :param kwargs: The requests kwargs from the original response
        :return: The TSRequest structure send from the server containing the pubKeyAuth for client to verify
        """
        if self.context.session_security is None:
            raise Exception("No session security was negotiated during the auth process. Cannot encrypt certificate")

        log.debug("_send_auth_response(): Generate the encrypted public key data and add it to the TSRequest")
        encrypted_public_key, public_key_signature = self.context.session_security.wrap(server_public_key)

        auth_nego_data = NegoData()
        auth_nego_data['nego_token'].value = authenticate_token

        ts_request = TSRequest()
        ts_request['nego_tokens'].value = auth_nego_data.get_data()
        ts_request['pub_key_auth'].value = public_key_signature + encrypted_public_key

        log.debug("_send_auth_response(): Send TSRequest structure containing "
                  "the final auth token and public key info")
        auth_credssp_token = self.wrap(ts_request.get_data())

        request = response.request.copy()
        self._set_credssp_token(request, auth_credssp_token)

        log.debug("_send_auth_response(): Get the public key structure response from the server")
        response = response.connection.send(request, **kwargs)
        response.content
        response.raw.release_conn()
        public_key_credssp_token = self._get_credssp_token(response)
        public_key_requests_data = self.unwrap(public_key_credssp_token)

        public_key_ts_request = TSRequest()
        public_key_ts_request.parse_data(public_key_requests_data)
        public_key_ts_request.check_error_code()

        if public_key_ts_request['pub_key_auth'].value is None:
            raise AuthenticationException('The server did not respond with pubKeyAuth info auth was rejected')

        return public_key_ts_request

    def _verify_public_keys(self, expected_key, public_key_ts_request):
        """
        [MS-CSSP] v13.0 2016-07-14

        3.1.5 Processing Events and Sequencing Rules - Step 4
        After the server received the public key in Step 3 it verifies the key with what was in the handshake.
        After the verification it then add 1 to the first byte representing the public key and encrypts the binary
        result by using the authentication protocol's encryption services.

        This method does the opposite where it will decrypt the public key returned from the server and subtract
        the first byte by 1 to compare with the public key we sent originally.

        :param expected_key: The ASN.1 encoded SubjectPublicKey field of the server X509 certificate
        :param public_key_ts_request: The TSRequest structure received from the server for host verification
        """
        log.debug("_verify_public_keys(): Get raw public key from the server and decrypt it for verification")
        raw_public_key = public_key_ts_request['pub_key_auth'].value

        # For NTLM signatures are always 16 bytes long, is it the same for Kerberos?
        public_key_signature = raw_public_key[:16]
        encrypted_public_key = raw_public_key[16:]
        public_key = self.context.session_security.unwrap(encrypted_public_key, public_key_signature)

        # Get the first byte from the server public key and subtract it by 1
        first_byte = public_key[0]

        # In Python 2 first_byte is a string so it needs to be unpacked. Python 3 it is a byte no unpacking is needed
        if isinstance(first_byte, str):
            first_byte = struct.unpack('B', first_byte)[0]

        new_byte = struct.pack('B', first_byte - 1)
        actual_key = new_byte + public_key[1:]

        assert actual_key == expected_key, "Could not verify key sent from the server, " \
                                           "possibly man in the middle attack"
        log.debug("_verify_public_keys(): verification of the server's public key is successful")

    def _send_encrypted_credentials(self, response, **kwargs):
        """
        [MS-CSSP] v13.0 2016-07-14

        3.1.5 Processing Events and Sequencing Rules - Step 5
        After the client has verified the server's authenticity, it encrypts the user's credentials with the
        authentication protocol's encryption services. The resulting value is encapsulated in the authInfo field of the
        TSRequest structure and sent over the encrypted TLS channel to the server

        :param response: The response from the server after completing the TLS handshake
        :param kwargs: The requests kwargs from the original response
        :return: The final response from the server after successful authentication, status code 200
        """
        ts_password_credentials = TSPasswordCreds()
        ts_password_credentials['domain_name'].value = self.domain.encode('utf-16le')
        ts_password_credentials['user_name'].value = self.user.encode('utf-16le')
        ts_password_credentials['password'].value = self.password.encode('utf-16le')

        ts_credentials = TSCredentials()
        # TODO: Add support for different credential types
        ts_credentials['cred_type'].value = struct.pack('B', 1)
        ts_credentials['credentials'].value = ts_password_credentials.get_data()

        credential_ts_request = TSRequest()
        encrypted_credential, encrypted_credential_sig = self.context.session_security.wrap(ts_credentials.get_data())
        credential_ts_request['auth_info'].value = encrypted_credential_sig + encrypted_credential

        credential_credssp_token = self.wrap(credential_ts_request.get_data())
        request = response.request.copy()
        self._set_credssp_token(request, credential_credssp_token)

        log.info("_send_encrypted_credentials(): Sending the encrypted credentials to the server")
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
                encrypted_chunk = self.tls_connection.bio_read(self.BIO_BUFFER_SIZE)
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
    def _parse_username(username):
        user = ''
        domain = '.'

        try:
            domain, user = username.split('\\', 1)
        except ValueError:
            try:
                user, domain = username.split('@', 1)
            except ValueError:
                user = username

        return domain, user

    @staticmethod
    def _check_credssp_supported(response):
        authenticate_header = response.headers.get('www-authenticate', '')
        if 'CREDSSP' not in authenticate_header.upper():
            raise AuthenticationException('The server did not respond with CredSSP as an available auth method')

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
            raise AuthenticationException("The server did not response with a CredSSP token, auth rejected")

    @staticmethod
    def _set_credssp_token(request, token):
        encoded_token = base64.b64encode(token)
        credssp_header = "CredSSP ".encode() + encoded_token
        request.headers['Authorization'] = credssp_header

    @staticmethod
    def _get_rsa_public_key(cert):
        """
        Written by Ian Clegg https://github.com/ianclegg/winrmlib/blob/master/winrmlib/api/authentication.py

        PyOpenSSL does not provide a public method to export the public key from a certificate as a properly formatted
        ASN.1 RSAPublicKey structure. There are 'hacks' which use dump_privatekey(crypto.FILETYPE_ASN1, <public_key>),
        but this dumps the public key within a PrivateKeyInfo structure which is not suitable for a comparison. This
        approach uses the PyOpenSSL CFFI bindings to invoke the i2d_RSAPublicKey() which correctly extracts the key
        material in an ASN.1 RSAPublicKey structure.
        :param cert: The ASN.1 Encoded Certificate
        :return: The ASN.1 Encoded RSAPublicKey structure containing the supplied certificates public Key
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
