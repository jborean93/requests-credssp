import binascii
import struct
try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict

import requests_credssp.asn_helper as asn_helper

from requests_credssp.exceptions import AsnStructureException, parse_nt_status_exceptions


class TSRequest(asn_helper.ASN1Sequence):
    """
    [MS-CSSP] v13.0 2016-07-14

    TSRequest ::= SEQUENCE {
        version     [0] INTEGER,
        negoTokens  [1] NegoData OPTIONAL,
        authInfo    [2] OCTET STRING OPTIONAL,
        pubKeyAuth  [3] OCTET STRING OPTIONAL,
        errorCode   [4] INTEGER OPTIONAL
    }

    The TSRequest struct is the top-most structure used by the CredSSP client and the CredSSP server. The TSRequest
    message is always sent over the TLS-encrypted channel between the client and the server in a CredSSP Protocol
    exchange.

    Fields:
        version: Specifies the support version of the CredSSP Protocol. Valid values for this field are 2 and 3
        negoTokens: A NegoData structure that contains the SPEGNO tokens or Kerberos/NTLM messages.
        authInfo: A TSCredentials structure that contains the user's credentials that are delegated to the server
        pubKeyAuth: Contains the server's public key info to stop man in the middle attacks
        errorCode: When version is 3, the server can send the NTSTATUS failure code (Only Server 2012 R2 and newer)
    """

    def __init__(self):
        self.name = 'TSRequest'
        self.type = asn_helper.ASN1_TYPE_SEQUENCE

        self.fields = OrderedDict()
        self['version'] = asn_helper.ASN1Field('version', 0xa0, asn_helper.ASN1_TYPE_INTEGER)
        self['nego_tokens'] = asn_helper.ASN1Field('negoTokens', 0xa1, asn_helper.ASN1_TYPE_SEQUENCE, True)
        self['auth_info'] = asn_helper.ASN1Field('authInfo', 0xa2, asn_helper.ASN1_TYPE_OCTET_STRING, True)
        self['pub_key_auth'] = asn_helper.ASN1Field('pubKeyInfo', 0xa3, asn_helper.ASN1_TYPE_OCTET_STRING, True)
        self['error_code'] = asn_helper.ASN1Field('errorCode', 0xa4, asn_helper.ASN1_TYPE_INTEGER, True)

        # When creating this object set the version to 3, if parsing data this value will be overwritten
        self['version'].value = struct.pack('B', 3)

    def parse_data(self, data):
        """
        Populates the TSRequest object with the data supplied. Need to override the default ASN1Sequence class
        as this structure has optional values which hasn't been implemented in the generic structure

        :param data: An ASN.1 data structure to be parsed
        """
        type_byte = struct.unpack('B', data[:1])[0]
        if type_byte != self.type:
            raise AsnStructureException("Expecting %s type to be (%x), was (%x)" % (self.name, self.type, type_byte))

        decoded_data, total_bytes = asn_helper.unpack_asn1(data)

        # Remove the bytes from the original type and length for comparison later
        total_bytes -= total_bytes - len(decoded_data)

        version_offset = asn_helper.parse_context_field(decoded_data, self['version'])
        new_offset = version_offset

        # Get the remaining values in the structure
        while new_offset !=  total_bytes:
            invalid_sequence = True
            field_data = decoded_data[new_offset:]
            sequence_byte = struct.unpack('B', field_data[:1])[0]

            for field in self.fields:
                field_info = self.fields[field]

                if sequence_byte == field_info.sequence:
                    invalid_sequence = False
                    value_offset = asn_helper.parse_context_field(field_data, self[field])
                    new_offset += value_offset

            if invalid_sequence:
                raise AsnStructureException('Unknown sequence byte (%x) in sequence' % sequence_byte)

    def check_error_code(self):
        """
        On CredSSP version 3 messages the server can respond with NTSTATUS error codes with the details
        of what went wrong. This method will check if the error code exists and throw an exception if
        it does.
        """
        if self['version'].value == struct.pack('B', 3):
            error_code = self['error_code'].value
            if error_code is not None:
                hex_error = binascii.hexlify(error_code)
                parse_nt_status_exceptions(hex_error)

class NegoData(asn_helper.ASN1Sequence):
    """
    [MS-CSSP] v13.0 2016-07-14

    NegoData ::= SEQUENCE OF SEQUENCE {
        negoToken [0] OCTET STRING
    }
    The NegoData structure contains the SPEGNO tokens, the Kerberos messages, or the NTLM messages.

    Fields:
        negoToken: One or more SPEGNO tokens, Kerberos messages or NTLM messages used for intial auth
    """

    def __init__(self):
        self.name = 'NegoData'
        self.type = asn_helper.ASN1_TYPE_SEQUENCE

        self.fields = OrderedDict()
        self['nego_token'] = asn_helper.ASN1Field('negoToken', 0xa0, asn_helper.ASN1_TYPE_OCTET_STRING)


class TSCredentials(asn_helper.ASN1Sequence):
    """
    [MS-CSSP] v13.0 2016-07-14

    TSCredentials ::= SEQUENCE {
        credType    [0] INTEGER,
        credentials [1] OCTET STRING
    }
    The TS Credentials structure contains both the user's credentials that are delegated to the server and their type.

    Fields:
        credType: Defines the type of credentials that are carried in the credentials field. (1, 2 or 6)
        credentials: Contains the user's credentials based on the credType structure above. Only TSPasswordCreds (1) right now
    """
    def __init__(self):
        self.name = 'TSCredentials'
        self.type = asn_helper.ASN1_TYPE_SEQUENCE

        self.fields = OrderedDict()
        self['cred_type'] = asn_helper.ASN1Field('credType', 0xa0, asn_helper.ASN1_TYPE_INTEGER)
        self['credentials'] = asn_helper.ASN1Field('credentials', 0xa1, asn_helper.ASN1_TYPE_OCTET_STRING)

class TSPasswordCreds(asn_helper.ASN1Sequence):
    """
    [MS-CSSP] v13.0 2016-07-14

    TSPasswordCreds ::= SEQUENCE {
        domainName  [0] OCTET STRING,
        userName    [1] OCTET STRING,
        password    [2] OCTET STRING
    }

    The TSPasswordCreds structure contains the user's password credentials that are delegated to the server.

    Fields:
        domainName: Contains the name of the user's account domain
        userName: Contains the user's account name
        password: Contains the user's account password
    """
    def __init__(self):
        self.name = 'TSPasswordCreds'
        self.type = asn_helper.ASN1_TYPE_SEQUENCE

        self.fields = OrderedDict()
        self['domain_name'] = asn_helper.ASN1Field('domainName', 0xa0, asn_helper.ASN1_TYPE_OCTET_STRING)
        self['user_name'] = asn_helper.ASN1Field('userName', 0xa1, asn_helper.ASN1_TYPE_OCTET_STRING)
        self['password'] = asn_helper.ASN1Field('password', 0xa2, asn_helper.ASN1_TYPE_OCTET_STRING)

"""
TODO: Add support for TSSmartCardCreds and TSRemoteGuardCreds

These are different delegation options that are supported by CredSSP

TSSmartCardCreds ::= SEQUENCE {
    pin         [0] OCTET STRING,
    cspData     [1] TSCspDataDetail,
    userHint    [2] OCTET STRING OPTIONAL,
    domainHint  [3] OCTET STRING OPTIONAL
}

TSRemoteGuardCreds ::= SEQUENCE {
    logonCred           [0] TSRemoteGuardPackageCred,
    supplementalCreds   [1] SEQUENCE OF TSRemoteGuardPackageCred OPTIONAL
}
"""
