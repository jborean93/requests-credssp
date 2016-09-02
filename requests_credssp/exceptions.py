class NTStatusCodes(object):
    # TODO: Fill in more exception types as they are found
    STATUS_LOGON_FAILURE = b'c000006d'

def parse_nt_status_exceptions(hex_code):
    """
    Loops through the exists NTStatusCode constants defined and will print out the exception details if found.

    :param code: The NTSTATUS hex code returned from the server under the TSRequest field errorCode
    """
    for status_name, status_value in vars(NTStatusCodes).items():
        if not status_name.startswith("__"):
            if hex_code == status_value:
                raise NTStatusException('%s - %s' % (status_name, status_value))

    raise NTStatusException('NTSTATUS error: Not Defined %s' % hex_code)

class NTStatusException(Exception):
    # Exception when receiving NTSTATUS codes in the TSRequest from the server
    pass

class AuthenticationException(Exception):
    # Authentication was rejected by the server
    pass

class AsnStructureException(Exception):
    # Failed to parse, create ASN.1 structures with the data supplied
    pass

class InvalidConfigurationException(Exception):
    # Config option is invalid and illegal
    pass