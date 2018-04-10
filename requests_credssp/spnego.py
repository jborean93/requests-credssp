# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import binascii
import logging

from abc import ABCMeta, abstractmethod
from ntlm_auth.ntlm import Ntlm
from six import with_metaclass

from requests_credssp.exceptions import AuthenticationException, \
    InvalidConfigurationException

HAS_GSSAPI = True
try:  # pragma: no cover
    import gssapi
    from gssapi.raw import acquire_cred_with_password
    from gssapi.raw import set_sec_context_option
except ImportError:
    HAS_GSSAPI = False

HAS_SSPI = True
try:  # pragma: no cover
    import sspi
    import sspicon
    import win32security
except ImportError:
    HAS_SSPI = False

log = logging.getLogger(__name__)


def get_auth_context(hostname, username, password, auth_mech):
    """
    Returns an AuthContext used in the CredSSP authentication process and to
    wrap/unwrap tokens sent to and from the client. This step get's the context
    based on the auth_mech configured and what is available on the server. It
    tries to favour system libraries like SSPI (Windows) or GSSAPI (Unix) if
    possible but falls back to a Python implementation of NTLM that works on
    all platforms.

    While in some cases the system libraries are used and they may not require
    a password to authenticate, CredSSP requires the password as it is sent
    to the remote host and so we won't rely on the user's logon tokens.

    :param hostname: The hostname of the server, this should be the FQDN when
        kerberos is desired
    :param username: The username to authenticate with
    :param password: The password of username
    :param auth_mech: The authentication mechanism to use;
        auto: Uses the SPNEGO/Negotiate mechanism which tries Kerberos if
            possible and then falls back to NTLM
        kerberos: Only allow authentication with Kerberos
        ntlm: Only allow authentication with NTLM
    :return: tuple
        AuthContext: The authentication context chosen that has been init
        generator step: The Python generator that takes further input tokens
            and produces output tokens to send to the server
        bytes first token: The first output token to send to the server
    """
    if auth_mech not in ["auto", "ntlm", "kerberos"]:
        raise InvalidConfigurationException("Invalid auth_mech supplied "
                                            "%s, must be auto, ntlm, or "
                                            "kerberos" % auth_mech)
    context_init = False
    out_token = None
    context_gen = None

    if HAS_SSPI:
        # always use SSPI when it is available
        log.info("SSPI is available and will be used as auth backend")
        context = SSPIContext(hostname, username, password, auth_mech)
    elif HAS_GSSAPI:
        mechs_available = ["kerberos"]
        # to save on computing costs we only check the mechs that are available
        # when auth_mech is auto or ntlm as it doesn't matter when kerberos
        # is set (Kerberos is always available when python-gssapi is installed
        if auth_mech != "kerberos":
            log.info("GSSAPI is available, determine what mechanism to use as "
                     "auth backend")
            mechs_available = GSSAPIContext.get_mechs_available()

        log.debug("GSSAPI mechs available: %s" % ", ".join(mechs_available))
        if auth_mech in mechs_available or auth_mech == "kerberos":
            log.info("GSSAPI with mech %s is being used as auth backend"
                     % auth_mech)
            context = GSSAPIContext(hostname, username, password, auth_mech)
        elif auth_mech == "ntlm":
            log.info("GSSAPI is available but does not support NTLM, using "
                     "ntlm-auth as auth backend instead")
            context = NTLMContext(username, password)
        else:
            # make sure we can actually initialise a GSSAPI context in auto,
            # otherwise fallback to NTLMContext if that fails
            # we need to explicitly set auth_mech as kerberos if the GSSAPI
            # implementation does not support NTLM so we know to use NTLM if
            # GSSAPI fails
            try:
                log.debug("Attempting to use GSSAPI Kerberos as auth backend")
                context = GSSAPIContext(hostname, username, password,
                                        "kerberos")
                context.init_context()
                context_gen = context.step()
                out_token = next(context_gen)
                context_init = True
                log.info("GSSAPI with mech kerberos is being used as auth "
                         "backend")
            except gssapi.exceptions.GSSError as err:
                log.warning("Failed to initialise GSSAPI context, falling "
                            "back to NTLM: %s" % str(err))
                context = NTLMContext(username, password)
    else:
        log.info("SSPI or GSSAPI is not available, using ntlm-auth as auth "
                 "backend")
        if auth_mech == "kerberos":
            raise InvalidConfigurationException("The auth_mechanism is set "
                                                "to kerberos but SSPI or "
                                                "GSSAPI is not available")
        context = NTLMContext(username, password)

    # we only init the context when HAS_GSSAPI and it doesn't natively offer
    # SPNEGO that works with Windows, so let's init it here
    if not context_init:
        context.init_context()
        context_gen = context.step()
        out_token = next(context_gen)

    return context, context_gen, out_token


class AuthContext(with_metaclass(ABCMeta, object)):
    _AUTH_MECHANISMS = {}

    def __init__(self, password, auth_mech):
        self.password = password
        self.auth_mech = self._AUTH_MECHANISMS[auth_mech]

        self._context = None

    @property
    @abstractmethod
    def domain(self):
        """
        The domain part of the username/domain combo. Each auth context
        handles this differently but it is used later in the CredSSP process
        when sending the encrypted credentials to the server.

        :return: string - the domain part of the username/domain combo
        """
        pass  # pragma: no cover

    @property
    @abstractmethod
    def username(self):
        """
        The username part of the username/domain combo. Each auth context
        handles this differently but it is used later in the CredSSP
        process when sending the encrypted credentials to the server.

        :return: string - the username part of the username/domain combo
        """
        pass  # pragma: no cover

    @property
    @abstractmethod
    def complete(self):
        """
        Whether the authentication phase between the client and server is
        complete

        :return: boolean - auth context is complete
        """
        pass  # pragma: no cover

    @abstractmethod
    def init_context(self):
        """
        Sets up the initial authentication context to get it ready to step.
        This must be called before step().
        """
        pass  # pragma: no cover

    @abstractmethod
    def step(self):
        """
        Generator that yields each authentication token to send to the server,
        it in turn takes in the response from the server and will continue
        until the authentication is complete
        """
        pass  # pragma: no cover

    @abstractmethod
    def wrap(self, data):
        """
        Used to wrap the data with the authentication context.

        :param data: The byte string to wrap
        :return: The byte string of the wrapped data
        """
        pass  # pragma: no cover

    @abstractmethod
    def unwrap(self, data):
        """
        Used to unwrap a response from the server that has been wrapped with
        the authentication context.

        :param data: The byte string of the wrapped data
        :return: The byte string of the unwrapped data
        """
        pass  # pragma: no cover

    @staticmethod
    def _get_domain_username(username):
        try:
            domain, username = username.split("\\", 1)
        except ValueError:
            username = username
            domain = ''
        return domain, username


class SSPIContext(AuthContext):
    _AUTH_MECHANISMS = {
        'auto': "Negotiate",
        'ntlm': "Ntlm",
        'kerberos': "Kerberos"
    }

    def __init__(self, hostname, username, password, auth_mech):
        super(SSPIContext, self).__init__(password, auth_mech)
        self._domain, self._username = self._get_domain_username(username)
        self._target_spn = "HTTP/%s" % hostname
        self._trailer_size = None
        self._call_counter = 0

    @property
    def domain(self):
        return self._domain

    @property
    def username(self):
        return self._username

    @property
    def complete(self):
        if self._context is None:
            return False
        return self._context.authenticated

    def init_context(self):
        flags = sspicon.ISC_REQ_INTEGRITY | \
                sspicon.ISC_REQ_CONFIDENTIALITY | \
                sspicon.ISC_REQ_REPLAY_DETECT | \
                sspicon.ISC_REQ_SEQUENCE_DETECT | \
                sspicon.ISC_REQ_MUTUAL_AUTH

        self._context = sspi.ClientAuth(
            pkg_name=self.auth_mech,
            auth_info=(self.username, self.domain, self.password),
            targetspn=self._target_spn,
            scflags=flags
        )

    def step(self):
        in_token = None
        while not self.complete:
            out_token = self._step(in_token)
            in_token = yield out_token if out_token != b"" else None

        # context is complete an no tokens need to be returned
        yield None

    def wrap(self, data):
        enc_data, trailer = self._context.encrypt(data)
        if self._trailer_size is None:
            # cannot use SECBUFFER_STREAM in unwrap due to heap corruption
            # this tells us the actual size of the trailer for the auth
            # negotiated so we know how to split the response
            self._trailer_size = len(trailer)
        return trailer + enc_data

    def unwrap(self, data):
        enc_data = data[self._trailer_size:]
        trailer = data[:self._trailer_size]
        dec_data = self._context.decrypt(enc_data, trailer)
        return dec_data

    def _step(self, token):
        success_codes = [
            sspicon.SEC_E_OK,
            sspicon.SEC_I_COMPLETE_AND_CONTINUE,
            sspicon.SEC_I_COMPLETE_NEEDED,
            sspicon.SEC_I_CONTINUE_NEEDED
        ]

        if token is not None:
            sec_buffer = win32security.PySecBufferDescType()
            sec_token = win32security.PySecBufferType(
                self._context.pkg_info['MaxToken'],
                sspicon.SECBUFFER_TOKEN
            )
            sec_token.Buffer = token
            sec_buffer.append(sec_token)
        else:
            sec_buffer = None

        rc, out_buffer = self._context.authorize(sec_buffer_in=sec_buffer)
        self._call_counter += 1
        if rc not in success_codes:
            rc_name = "Unknown Error"
            for name, value in vars(sspicon).items():
                if isinstance(value, int) and name.startswith("SEC_") and \
                        value == rc:
                    rc_name = name
                    break
            raise AuthenticationException("InitializeSecurityContext failed "
                                          "on call %d: (%d) %s 0x%s"
                                          % (self._call_counter, rc, rc_name,
                                             format(rc, 'x')))

        return out_buffer[0].Buffer


class GSSAPIContext(AuthContext):
    _AUTH_MECHANISMS = {
        'auto': "1.3.6.1.5.5.2",  # SPNEGO OID
        'kerberos': "1.2.840.113554.1.2.2",
        'ntlm': "1.3.6.1.4.1.311.2.2.10"
    }

    def __init__(self, hostname, username, password, auth_mech):
        super(GSSAPIContext, self).__init__(password, auth_mech)
        self._username = username
        self._hostname = hostname

        self._target_spn = "http@%s" % hostname
        self._complete = False

    @property
    def domain(self):
        return ""

    @property
    def username(self):
        return self._username

    @property
    def complete(self):
        if self._context is None:
            return self._complete
        elif self._complete:
            # used in NTLM scenarios once the msg3 is sent so CredSSP can send
            # it with the pubKeyAuth structure
            return True
        else:
            return self._context.complete

    def init_context(self):
        if self.auth_mech != self._AUTH_MECHANISMS['kerberos']:
            name_type = gssapi.NameType.user
        else:
            name_type = gssapi.NameType.kerberos_principal
        mech = gssapi.OID.from_int_seq(self.auth_mech)

        log.debug("GSSAPI: Acquiring security context for user %s with mech %s"
                  % (self.username, self.auth_mech))
        self._context = self._get_security_context(name_type, mech,
                                                   self._target_spn,
                                                   self.username,
                                                   self.password)

    def step(self):
        in_token = None
        while not self.complete:
            log.info("GSSAPI: Calling gss_init_sec_context()")
            out_token = self._context.step(in_token)

            # When generating the last NTLM message, we need to override
            # the complete status so CredSSP sends it with the pubKeyAuth
            if out_token and b"NTLMSSP\x00\x03\x00\x00\x00" in out_token:
                self._complete = True

            in_token = yield out_token

        # one final step for the mechListMIC when using NTLM
        self._context.step(in_token)

    def wrap(self, data):
        return self._context.wrap(data, True)[0]

    def unwrap(self, data):
        return self._context.unwrap(data)[0]

    @staticmethod
    def get_mechs_available():
        """
        Returns a list of auth mechanisms that are available to the local
        GSSAPI instance. Because we are interacting with Windows, we only
        care if SPNEGO, Kerberos and NTLM are available where NTLM is the
        only wildcard that may not be available by default.

        The only NTLM implementation that works properly is gss-ntlmssp and
        part of this test is to verify the gss-ntlmssp OID
        GSS_NTLMSSP_RESET_CRYPTO_OID_LENGTH is implemented which is required
        for SPNEGO and NTLM to work properly.

        :return: list - A list of supported mechs available in the installed
            version of GSSAPI
        """
        ntlm_oid = GSSAPIContext._AUTH_MECHANISMS['ntlm']
        ntlm_mech = gssapi.OID.from_int_seq(ntlm_oid)
        # GSS_NTLMSSP_RESET_CRYPTO_OID_LENGTH
        # github.com/simo5/gss-ntlmssp/blob/master/src/gssapi_ntlmssp.h#L68
        reset_mech = gssapi.OID.from_int_seq("1.3.6.1.4.1.7165.655.1.3")

        try:
            # we don't actually care about the account used here so just use
            # a random username and password
            ntlm_context = GSSAPIContext._get_security_context(
                gssapi.NameType.user,
                ntlm_mech,
                "http@server",
                "username",
                "password"
            )
            ntlm_context.step()
            set_sec_context_option(reset_mech, context=ntlm_context,
                                   value=b"\x00" * 4)
        except gssapi.exceptions.GSSError as exc:
            # failed to init NTLM and verify gss-ntlmssp is available, this
            # means NTLM is either not available or won't work
            # (not gss-ntlmssp) so we return kerberos as the only available
            # mechanism for the GSSAPI Context
            log.debug("Failed to init test NTLM context with GSSAPI: %s"
                      % str(exc))
            return ['kerberos']
        else:
            return ['auto', 'kerberos', 'ntlm']

    @staticmethod
    def _get_security_context(name_type, mech, spn, username, password):
        user = gssapi.Name(base=username,
                           name_type=name_type)
        server_name = gssapi.Name(spn,
                                  name_type=gssapi.NameType.hostbased_service)

        # acquire_cred_with_password is an expensive operation with Kerberos,
        # we will first attempt to just retrieve from the local credential
        # cache and if that fails we then acquire with the password. This is
        # only relevant to the Kerberos mech as NTLM and SPNEGO require us to
        # acquire with the password
        acquire_with_pass = True
        kerb_oid = GSSAPIContext._AUTH_MECHANISMS['kerberos']
        kerb_mech = gssapi.OID.from_int_seq(kerb_oid)
        if mech == kerb_mech:
            try:
                cred = gssapi.Credentials(name=user, usage='initiate',
                                          mechs=[mech])
                # we successfully got the Kerberos credential from the cache
                # and don't need to acquire with the password
                acquire_with_pass = False
            except gssapi.exceptions.GSSError:
                pass

        if acquire_with_pass:
            # error when trying to access the existing cache, get our own
            # credentials with the password specified
            b_password = password.encode('utf-8')
            cred = acquire_cred_with_password(user, b_password,
                                              usage='initiate',
                                              mechs=[mech])
            cred = cred.creds

        flags = gssapi.RequirementFlag.confidentiality | \
            gssapi.RequirementFlag.mutual_authentication | \
            gssapi.RequirementFlag.integrity | \
            gssapi.RequirementFlag.out_of_sequence_detection

        context = gssapi.SecurityContext(name=server_name,
                                         creds=cred,
                                         usage='initiate',
                                         mech=mech,
                                         flags=flags)
        return context


class NTLMContext(AuthContext):
    # this only supports NTLM and is meant to be a fallback in case SSPI or
    # GSSAPI is not installed or NTLM was chosen
    _AUTH_MECHANISMS = {
        'ntlm': ""
    }

    def __init__(self, username, password):
        super(NTLMContext, self).__init__(password, "ntlm")
        self._domain, self._username = self._get_domain_username(username)
        self._complete = False

    @property
    def domain(self):
        return self._domain

    @property
    def username(self):
        return self._username

    @property
    def complete(self):
        return self._complete

    def init_context(self):
        self._context = Ntlm()

    def step(self):
        msg1 = self._context.create_negotiate_message(self.domain)
        msg1 = base64.b64decode(msg1)
        log.debug("NTLM Negotiate message: %s" % binascii.hexlify(msg1))

        msg2 = yield msg1
        log.info("NTLM: Parsing Challenge message: %s"
                 % binascii.hexlify(msg2))
        msg2 = base64.b64encode(msg2)
        self._context.parse_challenge_message(msg2)

        log.info("NTLM: Generating Authenticate message")
        msg3 = self._context.create_authenticate_message(
            user_name=self.username,
            password=self.password,
            domain_name=self.domain
        )
        self._complete = True
        yield base64.b64decode(msg3)

    def wrap(self, data):
        enc_data, enc_signature = self._context.session_security.wrap(data)
        return enc_signature + enc_data

    def unwrap(self, data):
        return self._context.session_security.unwrap(data[16:], data[:16])
