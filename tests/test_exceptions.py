import pytest

from requests_credssp.exceptions import AuthenticationException, \
    InvalidConfigurationException, NtStatusCodes, NTStatusException


class TestAuthenticationException(object):

    def test_throw_authentication_exception(self):
        with pytest.raises(AuthenticationException) as exc:
            raise AuthenticationException("error")
        assert str(exc.value) == "error"


class TestInvalidConfigurationException(object):

    def test_throw_invalid_configuration_exception(self):
        with pytest.raises(InvalidConfigurationException) as exc:
            raise InvalidConfigurationException("error")
        assert str(exc.value) == "error"


class TestNTStatusException(object):

    def test_exception_with_known_code(self):
        with pytest.raises(NTStatusException) as exc:
            raise NTStatusException(NtStatusCodes.STATUS_LOGON_FAILURE)
        assert exc.value.status == NtStatusCodes.STATUS_LOGON_FAILURE
        assert str(exc.value) == "Received error status from the server: " \
                                 "(3221225581) STATUS_LOGON_FAILURE 0xc000006d"

    def test_exception_with_unknown_code(self):
        with pytest.raises(NTStatusException) as exc:
            raise NTStatusException(1)
        assert exc.value.status == 1
        assert str(exc.value) == "Received error status from the server: " \
                                 "(1) UNKOWN_STATUS 0x1"
