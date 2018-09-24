# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import binascii
import hashlib
import logging
import os
import re
import struct
import warnings

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from OpenSSL import SSL
from pyasn1.codec.der import encoder, decoder
from requests.auth import AuthBase

from requests_credssp.asn_structures import NegoToken, TSCredentials, \
    TSPasswordCreds, TSRequest
from requests_credssp.exceptions import AuthenticationException
from requests_credssp.spnego import get_auth_context

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

log = logging.getLogger(__name__)


class CredSSPContext(object):
    BIO_BUFFER_SIZE = 8192

    def __init__(self, hostname, username, password, auth_mechanism='auto',
                 disable_tlsv1_2=False, minimum_version=2):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.auth_mechanism = auth_mechanism
        self.minimum_version = minimum_version

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

    def credssp_generator(self):
        """
        [MS-CSSP] 3.1.5 Processing Events and Sequencing Rules
        https://msdn.microsoft.com/en-us/library/cc226791.aspx

        Generator function that yields each CredSSP token to sent to the
        server. CredSSP has multiple steps that must be run for the client to
        successfully authenticate with the server and delegate the credentials.
        """
        log.info("Starting TLS handshake process")
        self.tls_connection = SSL.Connection(self.tls_context)
        self.tls_connection.set_connect_state()

        while True:
            try:
                self.tls_connection.do_handshake()
            except SSL.WantReadError:
                out_token = self.tls_connection.bio_read(self.BIO_BUFFER_SIZE)
                log.debug("Step 1. TLS Handshake, returning token: %s"
                          % binascii.hexlify(out_token))
                in_token = yield out_token, "Step 1. TLS Handshake"
                log.debug("Step 1. TLS Handshake, received token: %s"
                          % binascii.hexlify(in_token))
                self.tls_connection.bio_write(in_token)
            else:
                break
        log.debug("TLS Handshake complete. Protocol: %s, Cipher: %s"
                  % (self.tls_connection.get_protocol_version_name(),
                     self.tls_connection.get_cipher_name()))

        server_certificate = self.tls_connection.get_peer_certificate()
        server_public_key = self._get_subject_public_key(server_certificate)

        log.info("Starting Authentication process")
        version = 6
        context, auth_step, out_token = get_auth_context(self.hostname,
                                                         self.username,
                                                         self.password,
                                                         self.auth_mechanism)
        while not context.complete:
            nego_token = NegoToken()
            nego_token['negoToken'] = out_token

            ts_request = TSRequest()
            ts_request['negoTokens'].append(nego_token)

            ts_request_token = encoder.encode(ts_request)
            log.debug("Step 2. Authenticate, returning token: %s"
                      % binascii.hexlify(ts_request_token))
            in_token = yield self.wrap(ts_request_token), \
                "Step 2. Authenticate"
            in_token = self.unwrap(in_token)
            log.debug("Step 3. Authenticate, received token: %s"
                      % binascii.hexlify(in_token))

            ts_request = decoder.decode(in_token, asn1Spec=TSRequest())[0]
            ts_request.check_error_code()
            version = int(ts_request['version'])
            out_token = \
                auth_step.send(bytes(ts_request['negoTokens'][0]['negoToken']))

        version = min(version, TSRequest.CLIENT_VERSION)
        log.info("Starting public key verification process at version %d"
                 % version)
        if version < self.minimum_version:
            raise AuthenticationException("The reported server version was %d "
                                          "and did not meet the minimum "
                                          "requirements of %d"
                                          % (version, self.minimum_version))
        if version > 4:
            nonce = os.urandom(32)
        else:
            log.warning("Reported server version was %d, susceptible to MitM "
                        "attacks and should be patched - CVE 2018-0886"
                        % version)
            nonce = None

        pub_key_auth = self._build_pub_key_auth(context, nonce,
                                                out_token,
                                                server_public_key)
        log.debug("Step 3. Server Authentication, returning token: %s"
                  % binascii.hexlify(pub_key_auth))
        in_token = yield (self.wrap(pub_key_auth),
                          "Step 3. Server Authentication")
        in_token = self.unwrap(in_token)
        log.debug("Step 3. Server Authentication, received token: %s"
                  % binascii.hexlify(in_token))

        log.info("Starting server public key response verification")
        ts_request = decoder.decode(in_token, asn1Spec=TSRequest())[0]
        ts_request.check_error_code()
        if not ts_request['pubKeyAuth'].isValue:
            raise AuthenticationException("The server did not response with "
                                          "pubKeyAuth info, authentication "
                                          "was rejected")
        if len(ts_request['negoTokens']) > 0:
            # SPNEGO auth returned the mechListMIC for us to verify
            auth_step.send(bytes(ts_request['negoTokens'][0]['negoToken']))

        response_key = context.unwrap(bytes(ts_request['pubKeyAuth']))
        self._verify_public_keys(nonce, response_key, server_public_key)

        log.info("Sending encrypted credentials")
        enc_credentials = self._get_encrypted_credentials(context)

        yield self.wrap(enc_credentials), "Step 5. Delegate Credentials"

    def _build_pub_key_auth(self, context, nonce, auth_token, public_key):
        """
        [MS-CSSP] 3.1.5 Processing Events and Sequencing Rules - Step 3
        https://msdn.microsoft.com/en-us/library/cc226791.aspx

        This step sends the final SPNEGO token to the server if required and
        computes the value for the pubKeyAuth field for the protocol version
        negotiated.

        The format of the pubKeyAuth field depends on the version that the
        server supports.

        For version 2 to 4:
        The pubKeyAuth field is just wrapped using the authenticated context

        For versions 5 to 6:
        The pubKeyAuth is a sha256 hash of the server's public key plus a nonce
        and a magic string value. This hash is wrapped using the authenticated
        context and the nonce is added to the TSRequest alongside the nonce
        used in the hash calcs.

        :param context: The authenticated context
        :param nonce: If versions 5+, the nonce to use in the hash
        :param auth_token: If NTLM, this is the last msg (authenticate msg) to
            send in the same request
        :param public_key: The server's public key
        :return: The TSRequest as a byte string to send to the server
        """
        ts_request = TSRequest()

        if auth_token is not None:
            nego_token = NegoToken()
            nego_token['negoToken'] = auth_token
            ts_request['negoTokens'].append(nego_token)

        if nonce is not None:
            ts_request['clientNonce'] = nonce
            hash_input = b"CredSSP Client-To-Server Binding Hash\x00" + \
                         nonce + public_key
            pub_value = hashlib.sha256(hash_input).digest()
        else:
            pub_value = public_key

        enc_public_key = context.wrap(pub_value)
        ts_request['pubKeyAuth'] = enc_public_key

        return encoder.encode(ts_request)

    def _verify_public_keys(self, nonce, server_key, public_key):
        """
        [MS-CSSP] 3.1.5 Processing Events and Sequencing Rules - Step 4
        https://msdn.microsoft.com/en-us/library/cc226791.aspx

        The rules vary depending on the server version

        For version 2 to 4:
        After the server received the public key in Step 3 it verifies the key
        with what was in the handshake. After the verification it then adds 1
        to the first byte representing the public key and encrypts the bytes
        result by using the authentication protocol's encryption services.

        This method does the opposite where it will decrypt the public key
        returned from the server and subtract the first byte by 1 to compare
        with the public key we sent originally.

        For versions 5 to 6:
        A hash is calculated with the magic string value, the nonce that was
        sent to the server and the public key that was used. This is verified
        against the returned server public key.

        :param nonce: If version 5+, the nonce used in the hash calculations
        :param server_key: The unwrapped value returned in the
            TSRequest['pubKeyAuth'] field.
        :param public_key: The actual public key of the server
        """
        if nonce is not None:
            hash_input = b"CredSSP Server-To-Client Binding Hash\x00" + nonce \
                         + public_key
            actual = hashlib.sha256(hash_input).digest()
            expected = server_key
        else:
            first_byte = struct.unpack("B", server_key[0:1])[0]
            actual_first_byte = struct.pack("B", first_byte - 1)

            actual = actual_first_byte + server_key[1:]
            expected = public_key

        if actual != expected:
            raise AuthenticationException("Could not verify key sent from the "
                                          "server, potential man in the "
                                          "middle attack")

    def _get_encrypted_credentials(self, context):
        """
        [MS-CSSP] 3.1.5 Processing Events and Sequencing Rules - Step 5
        https://msdn.microsoft.com/en-us/library/cc226791.aspx

        After the client has verified the server's authenticity, it encrypts
        the user's credentials with the authentication protocol's encryption
        services. The resulting value is encapsulated in the authInfo field of
        the TSRequest structure and sent over the encrypted TLS channel to the
        server

        :param context: The authenticated security context
        :return: The encrypted TSRequest that contains the user's credentials
        """
        ts_password = TSPasswordCreds()
        ts_password['domainName'] = context.domain.encode('utf-16-le')
        ts_password['userName'] = context.username.encode('utf-16-le')
        ts_password['password'] = context.password.encode('utf-16-le')

        ts_credentials = TSCredentials()
        ts_credentials['credType'] = ts_password.CRED_TYPE
        ts_credentials['credentials'] = encoder.encode(ts_password)

        ts_request = TSRequest()
        enc_credentials = context.wrap(encoder.encode(ts_credentials))
        ts_request['authInfo'] = enc_credentials

        return encoder.encode(ts_request)

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
    def _get_subject_public_key(cert):
        """
        Returns the SubjectPublicKey asn.1 field of the SubjectPublicKeyInfo
        field of the server's certificate. This is used in the server
        verification steps to thwart MitM attacks.

        :param cert: X509 certificate from pyOpenSSL .get_peer_certificate()
        :return: byte string of the asn.1 DER encoded SubjectPublicKey field
        """
        public_key = cert.get_pubkey()
        cryptographic_key = public_key.to_cryptography_key()
        subject_public_key = cryptographic_key.public_bytes(Encoding.DER,
                                                            PublicFormat.PKCS1)
        return subject_public_key


class HttpCredSSPAuth(AuthBase):

    def __init__(self, username, password, auth_mechanism='auto',
                 disable_tlsv1_2=False, minimum_version=2):
        """
        Initialises the CredSSP auth handler for dealing with requests.

        :param username: The username including domain to auth with
            (DOMAIN\\USER or USER@DOMAIN.LOCAL), use the user@DOMAIN.LOCAL form
            when wanting to use Kerberos.
        :param password: The password for the user above to delegate to the
            server
        :param auth_mechanism: The authentication mechanism to use
            (default is auto): auto, ntlm, kerberos
        :param disable_tlsv1_2: Disable TLSv1.2 authentication and revert back
            to TLSv1.
        :param minimum_version: The minimum server version that can be
            authenticated against, set to 5 to ensure CVE 2018-0886 is always
            mitigated and older hosts can't be used.
        """
        self.username = username
        self.password = password
        self.auth_mechanism = auth_mechanism
        self.disable_tlsv1_2 = disable_tlsv1_2
        self.minimum_version = minimum_version
        self.contexts = {}

    def __call__(self, request):
        request.headers["Connection"] = "Keep-Alive"
        request.register_hook('response', self.response_hook)

        return request

    # DEPRECATED Properties and Functions - these should be accessed per host
    # in self.contexts['hostname']
    @property
    def tls_context(self):
        warnings.warn("Deprecated property tls_context, this property should "
                      "be accessed using the host context, "
                      "credssp['hostname'].tls_context", DeprecationWarning)
        host = next(iter(self.contexts))
        return self.contexts[host].tls_context

    @property
    def tls_connection(self):
        warnings.warn("Deprecated property tls_connection, this property "
                      "should be accessed using the host context, "
                      "credssp['hostname'].tls_connection", DeprecationWarning)
        host = next(iter(self.contexts))
        return self.contexts[host].tls_connection

    @property
    def cipher_negotiated(self):
        warnings.warn("Deprecated property cipher_negotiated, this property "
                      "should be accessed using the host context, "
                      "credssp['hostname'].tls_connection.get_cipher_name()",
                      DeprecationWarning)
        host = next(iter(self.contexts))
        return self.contexts[host].tls_connection.get_cipher_name()

    def wrap(self, data):
        warnings.warn("Deprecated function, wrap should be accessed using "
                      "the host context wrap function, "
                      "credssp['hostname'].wrap()", DeprecationWarning)
        host = next(iter(self.contexts))
        context = self.contexts[host]
        return context.wrap(data)

    def unwrap(self, encrypted_data):
        warnings.warn("Deprecated function, unwrap should be accessed using "
                      "the host context unwrap function, "
                      "credssp['hostname'].unwrap()", DeprecationWarning)
        host = next(iter(self.contexts))
        context = self.contexts[host]
        return context.unwrap(encrypted_data)
    # END Deprecated Properties and Functions

    def response_hook(self, response, **kwargs):
        if response.status_code == 401:
            self._check_credssp_supported(response)
            response = self.handle_401(response, **kwargs)

        return response

    def handle_401(self, response, **kwargs):
        host = urlparse(response.url).hostname
        context = CredSSPContext(host, self.username, self.password,
                                 self.auth_mechanism, self.disable_tlsv1_2,
                                 self.minimum_version)
        self.contexts[host] = context

        credssp_gen = context.credssp_generator()
        credssp_regex = re.compile("CredSSP ([^,\s]*)$", re.I)

        # loop through the CredSSP generator to exchange the tokens between the
        # client and the server until either an error occurs or we reached the
        # end of the exchange
        out_token, step_name = next(credssp_gen)
        while True:
            try:
                # consume content and release the original connection to allow
                # the new request to reuse the same one.
                response.content
                response.raw.release_conn()

                # create the request with the CredSSP token present
                request = response.request.copy()
                self._set_credssp_token(request, out_token)

                # send the request and get the response
                response = response.connection.send(request, **kwargs)
                if response.status_code == 200:
                    break

                # attempt to retrieve the CredSSP token response
                in_token = self._get_credssp_token(response, credssp_regex,
                                                   step_name)

                # send the input CredSSP token and get the next output token
                out_token, step_name = credssp_gen.send(in_token)
            except StopIteration:
                break

        return response

    @staticmethod
    def _check_credssp_supported(response):
        auth_supported = response.headers.get('www-authenticate', '')
        if 'CREDSSP' not in auth_supported.upper():
            error_msg = "The server did not response CredSSP being an " \
                        "available authentication method - actual: '%s'" \
                        % auth_supported
            raise AuthenticationException(error_msg)

    @staticmethod
    def _set_credssp_token(request, token):
        encoded_token = base64.b64encode(token)
        credssp_header = b"CredSSP " + encoded_token
        request.headers['Authorization'] = credssp_header

    @staticmethod
    def _get_credssp_token(response, pattern, step_name):
        auth_header = response.headers.get('www-authenticate', '')
        token_match = pattern.search(auth_header)

        if not token_match:
            error_msg = "Server did not response with a CredSSP " \
                        "token after step %s - actual '%s'" \
                        % (step_name, auth_header)
            raise AuthenticationException(error_msg)

        token = token_match.group(1)
        return base64.b64decode(token)
