# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import logging
import re
import spnego
import spnego.exceptions
import spnego.tls
import ssl
import sys
import typing

from requests.auth import AuthBase
from urllib.parse import urlparse

from requests_credssp.exceptions import AuthenticationException, InvalidConfigurationException, NTStatusException


log = logging.getLogger(__name__)


class CredSSPContext:

    def __init__(
        self,
        hostname: str,
        username: str,
        password: str,
        auth_mechanism: str = "auto",
        disable_tlsv1_2: bool = False,
        minimum_version: int = 2,
    ) -> None:
        self.hostname = hostname
        self.username = username
        self.password = password
        self.auth_mechanism = auth_mechanism
        self.minimum_version = minimum_version

        credential = spnego.Password(username=username, password=password)

        auth_kwargs: typing.Dict[str, typing.Any] = {}
        if auth_mechanism == "kerberos" or auth_mechanism == "ntlm":
            auth_kwargs["credssp_negotiate_context"] = spnego.client(
                credential,
                hostname=hostname,
                service="HTTP",
                protocol=auth_mechanism,
            )
        elif auth_mechanism != "auto":
            raise InvalidConfigurationException("Invalid auth_mechanism supplied %s, must be auto, ntlm, or kerberos"
                                                % auth_mechanism)

        if disable_tlsv1_2:
            tls_context = spnego.tls.default_tls_context(usage="initiate")

            # The minimum_version field requires OpenSSL 1.1.0g or newer, fallback to the deprecated method of setting
            # the OP_NO_* options.
            tls_version = getattr(ssl, "TLSVersion", None)
            if hasattr(tls_context.context, "minimum_version") and tls_version:
                setattr(tls_context.context, "minimum_version", tls_version.TLSv1)
            else:
                tls_context.context.options &= ~ssl.OP_NO_TLSv1 & ~ssl.OP_NO_TLSv1_1

            auth_kwargs["credssp_tls_context"] = tls_context

        if minimum_version > 2:
            auth_kwargs["credssp_min_protocol"] = minimum_version

        self._context = spnego.client(
            credential,
            hostname=hostname,
            service="HTTP",
            protocol="credssp",
            **auth_kwargs,
        )

    @property
    def tls_connection(self) -> typing.Optional[ssl.SSLObject]:
        ssl_object = self._context.get_extra_info("ssl_object") if self._context else None

        # Older pywinrm and pypsrp still use this to get the cipher for wrapping.
        # Until they've been migrated over to (un)wrap_winrm it needs to stay.
        def get_cipher_name():
            details = ssl_object.cipher()
            if details:
                return details[0]

        setattr(ssl_object, "get_cipher_name", get_cipher_name)

        return ssl_object

    def credssp_generator(self) -> typing.Generator[typing.Tuple[bytes, str], bytes, None]:
        """
        [MS-CSSP] 3.1.5 Processing Events and Sequencing Rules
        https://msdn.microsoft.com/en-us/library/cc226791.aspx

        Generator function that yields each CredSSP token to sent to the
        server. CredSSP has multiple steps that must be run for the client to
        successfully authenticate with the server and delegate the credentials.
        """
        in_token = None
        while not self._context.complete:
            try:
                out_token = self._context.step(in_token)
            except spnego.exceptions.SpnegoError as e:
                # For backwards compatibility, base_error is not set if an authentication failure happened. If it is
                # set then it's treated as an error from the peer and raises as an NTStatusException.
                if e.base_error is None or e.nt_status == 0xFFFFFFFF:
                    raise AuthenticationException(str(e)) from e
                else:
                    # Value in SpnegoError is signed but NTStatusException expects an unsigned value
                    nt_status = e.nt_status
                    if nt_status < 0:
                        b_nt_status = nt_status.to_bytes(4, byteorder=sys.byteorder, signed=True)
                        nt_status = int.from_bytes(b_nt_status, byteorder=sys.byteorder, signed=False)
                    raise NTStatusException(nt_status, str(e)) from e

            current_step = self._context.get_extra_info("auth_stage", "Unknown")
            in_token = yield out_token, current_step

    def wrap(
        self,
        data: bytes,
    ) -> bytes:
        """
        Encrypts the data in preparation for sending to the server. The data is
        encrypted using the TLS channel negotiated between the client and the
        server.

        :param data: a byte string of data to encrypt
        :return: a byte string of the encrypted data
        """
        return self._context.wrap(data).data

    def wrap_winrm(
        self,
        data: bytes,
    ) -> typing.Tuple[bytes, bytes, int]:
        return self._context.wrap_winrm(data)

    def unwrap(
        self,
        data: bytes,
    ) -> bytes:
        """
        Decrypts the data send by the server using the TLS channel negotiated
        between the client and the server.

        :param encrypted_data: the byte string of the encrypted data
        :return: a byte string of the decrypted data
        """
        return self._context.unwrap(data).data

    def unwrap_winrm(
        self,
        header: bytes,
        data: bytes,
    ) -> bytes:
        return self._context.unwrap_winrm(header, data)


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
        self.contexts: typing.Dict[str, CredSSPContext] = {}

    def __call__(self, request):
        request.headers["Connection"] = "Keep-Alive"
        request.register_hook('response', self.response_hook)

        return request

    def response_hook(self, response, **kwargs):
        if response.status_code == 401:
            self._check_credssp_supported(response)
            response = self.handle_401(response, **kwargs)

        return response

    def handle_401(self, response, **kwargs):
        host = urlparse(response.url).hostname
        context = CredSSPContext(host, self.username, self.password, self.auth_mechanism, self.disable_tlsv1_2,
                                 self.minimum_version)
        self.contexts[host] = context

        credssp_gen = context.credssp_generator()
        credssp_regex = re.compile(r"CredSSP ([^,\s]*)$", re.I)

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
                in_token = self._get_credssp_token(response, credssp_regex, step_name)

                # send the input CredSSP token and get the next output token
                out_token, step_name = credssp_gen.send(in_token)
            except StopIteration:
                break

        return response

    @staticmethod
    def _check_credssp_supported(response):
        auth_supported = response.headers.get('www-authenticate', '')
        if 'CREDSSP' not in auth_supported.upper():
            error_msg = "The server did not response CredSSP being an available authentication method - actual: '%s'" \
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
            error_msg = "Server did not response with a CredSSP token after step %s - actual '%s'" \
                        % (step_name, auth_header)
            raise AuthenticationException(error_msg)

        token = token_match.group(1)
        return base64.b64decode(token)
