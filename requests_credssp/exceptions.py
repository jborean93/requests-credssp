# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)


class NtStatusCodes(object):
    STATUS_SUCCESS = 0x00000000
    STATUS_INVALID_HANDLE = 0xC0000008
    STATUS_LOGON_FAILURE = 0xC000006D
    STATUS_ACCOUNT_RESTRICTION = 0xC000006E
    STATUS_INVALID_LOGON_HOURS = 0xC000006F
    STATUS_INVALID_WORKSTATION = 0xC0000070
    STATUS_PASSWORD_EXPIRED = 0xC0000071
    STATUS_ACCOUNT_DISABLED = 0xC0000072
    STATUS_INSUFFICIENT_RESOURCES = 0xC000009A
    STATUS_NOT_SUPPORTED = 0xC00000BB

    # HRESULT Values - used in SPNEGO responses
    SEC_E_INVALID_TOKEN = 0x80090308
    SEC_E_MESSAGE_ALTERED = 0x8009030F


class AuthenticationException(Exception):
    # Authentication was rejected by the server
    pass


class InvalidConfigurationException(Exception):
    # Config option is invalid and illegal
    pass


class NTStatusException(Exception):
    # Exception when receiving NTSTATUS codes in the TSRequest from the server

    @property
    def status(self):
        return self.args[0]

    @property
    def message(self):
        status_name = None
        for status, status_value in vars(NtStatusCodes).items():
            if status_value == self.status:
                status_name = status
                break

        return "Received error status from the server: (%d) %s 0x%s" \
               % (self.status, status_name if status_name else "UNKOWN_STATUS",
                  format(self.status, 'x'))

    def __str__(self):
        return self.message
