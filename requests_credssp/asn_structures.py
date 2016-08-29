import struct
import asn_helper
try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict


class TSRequest(object):
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

    def __getitem__(self, item):
        return self.fields[item]

    def __setitem__(self, key, value):
        self.fields[key] = value

    def parse_data(self, data):
        """
        Populates the TSRequest object with the data supplied.

        :param data: An ASN.1 data structure to be decoded
        """
        type_byte = struct.unpack('B', data[:1])[0]
        if type_byte != self.type:
            raise Exception("Expecting %s type to be (%x), was (%x)" % (self.name, self.type, type_byte))

        decoded_data, total_bytes = asn_helper.asn1decode(data[1:])

        version_offset = asn_helper.parse_asn1_field(decoded_data, self['version'])
        new_offset = version_offset

        while new_offset < total_bytes:
            field_data = decoded_data[new_offset:]
            sequence_byte = struct.unpack('B', field_data[:1])[0]

            if sequence_byte == 0xa1:
                nego_token_offset = asn_helper.parse_asn1_field(field_data, self['nego_tokens'])
                new_offset += nego_token_offset + 3

            elif sequence_byte == 0xa2:
                auth_info_offset = asn_helper.parse_asn1_field(field_data, self['auth_info'])
                new_offset += auth_info_offset + 1

            elif sequence_byte == 0xa3:
                pub_key_auth_offset = asn_helper.parse_asn1_field(field_data, self['pub_key_auth'])
                new_offset += pub_key_auth_offset + 2

            elif sequence_byte == 0xa4:
                error_code_offset = asn_helper.parse_asn1_field(field_data, self['error_code'])
                new_offset += error_code_offset

            else:
                raise Exception('Unknown sequence byte in sequence')

        #assert new_offset == total_bytes


    def get_data(self):
        """
        Creates an ASN.1 data structure based on the values already set in the object. This does not include
        the ERROR_CODE field as that is only used by the server to identify issues to the client.

        :return: An ASN.1 data structure to send to the server.
        """

        values = ''
        for field in self.fields:
            value = asn_helper.get_asn1_field(self[field])
            values += value

        data = struct.pack('B', self.type)
        data += asn_helper.asn1encode(values)

        return data

class NegoData(object):
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

    def __getitem__(self, item):
        return self.fields[item]

    def __setitem__(self, key, value):
        self.fields[key] = value

    def parse_data(self, data):
        type_byte = struct.unpack('B', data[:1])[0]
        if type_byte != self.type:
            raise Exception("Expecting %s type to be (%x), was (%x)" % (self.name, self.type, type_byte))

        decoded_data, total_bytes = asn_helper.asn1decode(data[1:])
        new_offset = 0
        for field in self.fields:
            offset = asn_helper.parse_asn1_field(decoded_data, self[field])
            new_offset += offset

        new_offset += 2

        #assert new_offset == total_bytes

    def get_data(self):
        """
            Creates an ASN.1 data structure based on the values already set in the object. This does not include
            the ERROR_CODE field as that is only used by the server to identify issues to the client.

            :return: An ASN.1 data structure to send to the server.
            """

        values = ''
        for field in self.fields:
            value = asn_helper.get_asn1_field(self[field])
            values += value

        data = struct.pack('B', self.type)
        data += asn_helper.asn1encode(values)

        return data

class TSCredentials(object):
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

    def __getitem__(self, item):
        return self.fields[item]

    def __setitem__(self, key, value):
        self.fields[key] = value

    def parse_data(self, data):
        type_byte = struct.unpack('B', data[:1])[0]
        if type_byte != self.type:
            raise Exception("Expecting %s type to be (%x), was (%x)" % (self.name, self.type, type_byte))

        decoded_data, total_bytes = asn_helper.asn1decode(data[1:])

        cred_type_offset = asn_helper.parse_asn1_field(decoded_data, self['cred_type'])
        new_offset = cred_type_offset

        decoded_data = decoded_data[new_offset:]
        credentials_offset = asn_helper.parse_asn1_field(decoded_data, self['credentials'])
        new_offset += credentials_offset

        #assert new_offset + 1 == total_bytes

    def get_data(self):
        """
            Creates an ASN.1 data structure based on the values already set in the object. This does not include
            the ERROR_CODE field as that is only used by the server to identify issues to the client.

            :return: An ASN.1 data structure to send to the server.
            """

        values = ''
        for field in self.fields:
            value = asn_helper.get_asn1_field(self[field])
            values += value

        data = struct.pack('B', self.type)
        data += asn_helper.asn1encode(values)

        return data

class TSPasswordCreds(object):
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

    def __getitem__(self, item):
        return self.fields[item]

    def __setitem__(self, key, value):
        self.fields[key] = value

    def parse_data(self, data):
        type_byte = struct.unpack('B', data[:1])[0]
        if type_byte != self.type:
            raise Exception("Expecting %s type to be (%x), was (%x)" % (self.name, self.type, type_byte))

        decoded_data, total_bytes = asn_helper.asn1decode(data[1:])

        domain_offset = asn_helper.parse_asn1_field(decoded_data, self['domain_name'])
        new_offset = domain_offset

        decoded_data = decoded_data[new_offset:]
        user_offset = asn_helper.parse_asn1_field(decoded_data, self['user_name'])
        new_offset += user_offset

        decoded_data = decoded_data[new_offset:]
        password_offset = asn_helper.parse_asn1_field(decoded_data, self['password'])
        new_offset += password_offset

        #assert new_offset == total_bytes

    def get_data(self):
        """
            Creates an ASN.1 data structure based on the values already set in the object. This does not include
            the ERROR_CODE field as that is only used by the server to identify issues to the client.

            :return: An ASN.1 data structure to send to the server.
            """

        values = ''
        for field in self.fields:
            value = asn_helper.get_asn1_field(self[field])
            values += value

        data = struct.pack('B', self.type)
        data += asn_helper.asn1encode(values)

        return data

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
