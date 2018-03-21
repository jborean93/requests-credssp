import pytest

from requests_credssp.exceptions import InvalidConfigurationException
from requests_credssp.spnego import AuthContext, GSSAPIContext, NTLMContext, \
    SSPIContext, get_auth_context


class TestGetAuthContext(object):

    def get_auth_invalid_mech(self):
        with pytest.raises(InvalidConfigurationException) as exc:
            get_auth_context("", "", "", "fake")
        assert str(exc.value) == "Invalid auth_mech supplied fake, must be " \
                                 "auto, ntlm, or kerberos"


class TestAuthContext(object):

    def test_username(self):
        actual_domain, actual_username = \
            AuthContext._get_domain_username("username")
        assert actual_domain == ""
        assert actual_username == "username"

    def test_netlogon_username(self):
        actual_domain, actual_username = \
            AuthContext._get_domain_username("DOMAIN\\username")
        assert actual_domain == "DOMAIN"
        assert actual_username == "username"

    def test_upn_username(self):
        actual_domain, actual_username = \
            AuthContext._get_domain_username("username@DOMAIN.LOCAL")
        assert actual_domain == ""
        assert actual_username == "username@DOMAIN.LOCAL"


class TestSSPIContext(object):

    def test_basic_init(self):
        # this only tests the basic structure as the rest requires Windows
        actual = SSPIContext("hostname", "username", "password", "auto")
        assert actual.domain == ""
        assert actual.username == "username"
        assert actual.auth_mech == "Negotiate"
        assert not actual.complete


class TestGSSAPIContext(object):

    def test_basic_init(self):
        actual = GSSAPIContext("hostname", "username", "password", "auto")
        assert actual.domain == ""
        assert actual.username == "username"
        assert actual.password == "password"
        assert actual.auth_mech == "1.3.6.1.5.5.2"
        assert not actual.complete


class TestNTLMContext(object):

    def test_ntlm_step(self):
        ntlm = NTLMContext("username", "password")
        ntlm.init_context()
        assert ntlm.domain == ""
        assert ntlm.username == "username"
        assert ntlm.password == "password"

        challenge_token = b'\x4E\x54\x4C\x4D\x53\x53\x50\x00' \
                          b'\x02\x00\x00\x00\x04\x00\x04\x00' \
                          b'\x38\x00\x00\x00\x36\x82\x89\xE2' \
                          b'\x45\x80\xF2\xD5\xB4\xF3\xED\x50' \
                          b'\x00\x00\x00\x00\x00\x00\x00\x00' \
                          b'\xB2\x00\xB2\x00\x3C\x00\x00\x00' \
                          b'\x06\x01\xB1\x1D\x00\x00\x00\x0F' \
                          b'\x43\x4F\x52\x50\x02\x00\x08\x00' \
                          b'\x43\x00\x4F\x00\x52\x00\x50\x00' \
                          b'\x01\x00\x1A\x00\x43\x00\x4F\x00' \
                          b'\x4D\x00\x50\x00\x55\x00\x54\x00' \
                          b'\x45\x00\x52\x00\x48\x00\x4F\x00' \
                          b'\x53\x00\x54\x00\x31\x00\x04\x00' \
                          b'\x1E\x00\x63\x00\x6F\x00\x72\x00' \
                          b'\x70\x00\x2E\x00\x6F\x00\x72\x00' \
                          b'\x67\x00\x2E\x00\x63\x00\x6F\x00' \
                          b'\x6D\x00\x2E\x00\x61\x00\x75\x00' \
                          b'\x03\x00\x3A\x00\x43\x00\x4F\x00' \
                          b'\x4D\x00\x50\x00\x55\x00\x54\x00' \
                          b'\x45\x00\x52\x00\x48\x00\x4F\x00' \
                          b'\x53\x00\x54\x00\x31\x00\x2E\x00' \
                          b'\x63\x00\x6F\x00\x72\x00\x70\x00' \
                          b'\x2E\x00\x6F\x00\x72\x00\x67\x00' \
                          b'\x2E\x00\x63\x00\x6F\x00\x6D\x00' \
                          b'\x2E\x00\x61\x00\x75\x00\x05\x00' \
                          b'\x14\x00\x6F\x00\x72\x00\x67\x00' \
                          b'\x2E\x00\x63\x00\x6F\x00\x6D\x00' \
                          b'\x2E\x00\x61\x00\x75\x00\x07\x00' \
                          b'\x08\x00\xC5\xBE\x86\x1B\x94\x04' \
                          b'\xD2\x01\x00\x00\x00\x00'

        step_gen = ntlm.step()
        msg1 = next(step_gen)
        assert not ntlm.complete
        assert isinstance(msg1, bytes)
        assert msg1[:9] == b"NTLMSSP\x00\x01"

        msg3 = step_gen.send(challenge_token)
        assert ntlm.complete
        assert isinstance(msg3, bytes)
        assert msg3[:9] == b"NTLMSSP\x00\x03"

        # the sign message and encrypted message should have different seq
        # numbers
        data = b"\x01\x02\x03\x04"
        enc_msg = ntlm.wrap(data)
        assert enc_msg != data

        # 0-4 is NTLM sig == 01 00 00 00 , 12:16 is the sequence number
        assert enc_msg[:4] == b"\x01\x00\x00\x00"
        assert enc_msg[12:16] == b"\x00\x00\x00\x00"

    def test_ntlm_unwrap(self):
        class SessionSecurityMock(object):
            def unwrap(self, data1, data2):
                # asserts NTLMContext actually splits the sig and data and
                # sends them to ntlm-auth correctly
                assert data1 == b"\xbb" * 16
                assert data2 == b"\xaa" * 16

        ntlm = NTLMContext("", "")
        ntlm.init_context()
        ntlm._context.session_security = SessionSecurityMock()

        data = (b"\xaa" * 16) + (b"\xbb" * 16)
        ntlm.unwrap(data)