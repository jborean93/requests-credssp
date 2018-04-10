# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import ctypes

from pyasn1.type.namedtype import NamedType, NamedTypes, OptionalNamedType
from pyasn1.type.tag import Tag, tagClassContext, tagFormatConstructed
from pyasn1.type.univ import Integer, OctetString, Sequence, SequenceOf

from requests_credssp.exceptions import NtStatusCodes, NTStatusException


class NegoToken(Sequence):
    componentType = NamedTypes(
        NamedType(
            'negoToken', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 0)
            )
        )
    )


class NegoData(SequenceOf):
    """
    [MS-CSSP] 2.2.1.1 NegoData
    https://msdn.microsoft.com/en-us/library/cc226781.aspx

    Contains the SPNEGO tokens, Kerberos or NTLM messages.

    NegoData ::= SEQUENCE OF SEQUENCE {
        negoToken [0] OCTET STRING
    }
    """
    componentType = NegoToken()


class TSRequest(Sequence):
    """
    [MS-CSSP] 2.2.1 TSRequest
    https://msdn.microsoft.com/en-us/library/cc226780.aspx

    Top-most structure used by the client and server and contains various
    different types of data depending on the stage of the CredSSP protocol it
    is at.

    TSRequest ::= SEQUENCE {
        version    [0] INTEGER,
        negoTokens [1] NegoData  OPTIONAL,
        authInfo   [2] OCTET STRING OPTIONAL,
        pubKeyAuth [3] OCTET STRING OPTIONAL,
        errorCode  [4] INTEGER OPTIONAL,
        clientNonce [5] OCTER STRING OPTIONAL,
    }

    Fields:
        version: Specifies the support version of the CredSSP Protocol. Valid
            values for this field are 2 and 3
        negoTokens: A NegoData structure that contains the SPEGNO tokens or
            Kerberos/NTLM messages.
        authInfo: A TSCredentials structure that contains the user's
            credentials that are delegated to the server
        pubKeyAuth: Contains the server's public key info to stop man in the
            middle attacks
        errorCode: When version is 3, the server can send the NTSTATUS failure
            codes (Only Server 2012 R2 and newer)
        clientNonce: A 32-byte array of cryptographically random bytes, only
            used in version 5 or higher of this protocol
    """
    CLIENT_VERSION = 6

    componentType = NamedTypes(
        NamedType(
            'version', Integer().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 0)
            )
        ),
        OptionalNamedType(
            'negoTokens', NegoData().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 1)
            )
        ),
        OptionalNamedType(
            'authInfo', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 2)
            )
        ),
        OptionalNamedType(
            'pubKeyAuth', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 3)
            )
        ),
        OptionalNamedType(
            'errorCode', Integer().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 4)
            )
        ),
        OptionalNamedType(
            'clientNonce', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 5)
            )
        )
    )

    def __init__(self, **kwargs):
        super(TSRequest, self).__init__(**kwargs)
        self['version'] = self.CLIENT_VERSION

    def check_error_code(self):
        """
        For CredSSP version of 3 or newer, the server can response with an
        NtStatus error code with details of what error occurred. This method
        will check if the error code exists and throws an NTStatusException
        if it is no STATUS_SUCCESS.
        """
        # start off with STATUS_SUCCESS as a baseline
        status = NtStatusCodes.STATUS_SUCCESS

        error_code = self['errorCode']
        if error_code.isValue:
            # ASN.1 Integer is stored as an signed integer, we need to
            # convert it to a unsigned integer
            status = ctypes.c_uint32(error_code).value

        if status != NtStatusCodes.STATUS_SUCCESS:
            raise NTStatusException(status)


class TSCredentials(Sequence):
    """
    [MS-CSSP] 2.2.1.2 TSCredentials
    https://msdn.microsoft.com/en-us/library/cc226782.aspx

    Contains the user's credentials and their type to send to the server.

    TSCredentials ::= SEQUENCE {
        credType    [0] INTEGER,
        credentials [1] OCTET STRING
    }
    """
    componentType = NamedTypes(
        NamedType(
            'credType', Integer().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 0)
            )
        ),
        NamedType(
            'credentials', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 1)
            )
        )
    )


class TSPasswordCreds(Sequence):
    """
    [MS-CSSP] 2.2.1.2.1 TSPasswordCreds
    https://msdn.microsoft.com/en-us/library/cc226783.aspx

    Contains the user's password credentials that are delegated to the server.

    TSPasswordCreds ::= SEQUENCE {
        domainName  [0] OCTET STRING,
        userName    [1] OCTET STRING,
        password    [2] OCTET STRING
    }
    """
    CRED_TYPE = 1  # 2.2.1.2 TSCredentials

    componentType = NamedTypes(
        NamedType(
            'domainName', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 0)
            )
        ),
        NamedType(
            'userName', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 1)
            )
        ),
        NamedType(
            'password', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 2)
            )
        ),
    )


"""
TODO: Add support for TSSmartCardCreds and TSRemoteGuardCreds

These are different delegation options that are supported by CredSSP

TSSmartCardCreds ::= SEQUENCE {  # CRED_TYPE = 2
    pin         [0] OCTET STRING,
    cspData     [1] TSCspDataDetail,
    userHint    [2] OCTET STRING OPTIONAL,
    domainHint  [3] OCTET STRING OPTIONAL
}

TSRemoteGuardCreds ::= SEQUENCE {  # CRED_TYPE = 6
    logonCred           [0] TSRemoteGuardPackageCred,
    supplementalCreds   [1] SEQUENCE OF TSRemoteGuardPackageCred OPTIONAL
}
"""
