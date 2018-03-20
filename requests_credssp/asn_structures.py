# Copyright: (c) 2018, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import ctypes

from pyasn1.type.constraint import SingleValueConstraint
from pyasn1.type.namedtype import NamedType, NamedTypes, OptionalNamedType
from pyasn1.type.namedval import NamedValues
from pyasn1.type.tag import Tag, tagClassApplication, tagClassContext, \
    tagFormatConstructed, tagFormatSimple, TagSet
from pyasn1.type.univ import BitString, Choice, Enumerated, Integer, \
    ObjectIdentifier, OctetString, Sequence, SequenceOf

from requests_credssp.exceptions import NtStatusCodes, NTStatusException


class SPNEGOMechs(object):
    SPNEGO = ObjectIdentifier('1.3.6.1.5.5.2')
    KRB5 = ObjectIdentifier('1.2.840.113554.1.2.2')
    NTLMSSP = ObjectIdentifier('1.3.6.1.4.1.311.2.2.10')


class SPNEGONegState(object):
    ACCEPT_COMPLETE = 0
    ACCEPT_INCOMPLETE = 1
    REJECT = 2
    REQUEST_MIC = 3


class MechType(ObjectIdentifier):
    """
    [RFC-4178] 4.1. Mechanism Types

    OID represents one GSS-API mechanism according to RFC-2743.

    MechType ::= OBJECT IDENTIFIER
    """
    pass


class MechTypeList(SequenceOf):
    """
    [RFC-4178] 4.1. Mechanism Types

    List of MechTypes

    MechTypeList ::= SEQUENCE OF MechType
    """
    componentType = MechType()


class ContextFlags(BitString):
    """
    [RFC-4178] 4.2.1. negTokenInit ContextFlags

    ContextFlags ::= BIT STRING {
        delegFlag (0),
        mutualFlag (1),
        replayFlag (2),
        sequenceFlag (3),
        anonFlag (4),
        confFlag (5),
        integFlag (6)
    }
    """
    componentType = NamedValues(
        ('delegFlag', 0),
        ('mutualFlag', 1),
        ('replayFlag', 2),
        ('sequenceFlag', 3),
        ('anonFlag', 4),
        ('confFlag', 5),
        ('integFlag', 6)
    )


class NegState(Enumerated):
    """
    [RFC-4178] 4.2.2. negTokenResp - negState

    NegState ::= ENUMERATED {
        accept-completed (0),
        accept-incomplete (1),
        reject (2),
        request-mic (3)
    }
    """
    namedValues = NamedValues(
        ('accept-complete', SPNEGONegState.ACCEPT_COMPLETE),
        ('accept-incomplete', SPNEGONegState.ACCEPT_INCOMPLETE),
        ('reject', SPNEGONegState.REJECT),
        ('request-mic', SPNEGONegState.REQUEST_MIC)
    )
    subtypeSpec = Enumerated.subtypeSpec + SingleValueConstraint(
        SPNEGONegState.ACCEPT_COMPLETE,
        SPNEGONegState.ACCEPT_INCOMPLETE,
        SPNEGONegState.REJECT,
        SPNEGONegState.REQUEST_MIC
    )


class NegTokenInit(Sequence):
    """
    [RFC-4178] 4.2.1. negTokenInit

    The initial message for SPNEGO messages.

    NegTokenInit ::= SEQUENCE {
        mechTypes   [0] MechTypeList,
        regFlags    [1] ContextFlags OPTIONAL,
        mechToken   [2] OCTET STRING OPTIONAL,
        mechListMIC [3] OCTER STRING OPTIONAL
    }
    """
    componentType = NamedTypes(
        NamedType(
            'mechTypes', MechTypeList().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 0)
            )
        ),
        OptionalNamedType(
            'reqFlags', ContextFlags().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 1)
            )
        ),
        OptionalNamedType(
            'mechToken', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 2)
            )
        ),
        OptionalNamedType(
            'mechListMIC', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 3)
            )
        )
    )


class NegTokenResp(Sequence):
    """
    [RFC-4178] 4.2.2. negTokenResp

    Used as the message structure for all subsequent SPNEGO messages.

    NegTokenResp ::= SEQUENCE {
        negState        [0] NegState OPTIONAL,
        supportedMech   [1] MechType OPTIONAL,
        responseToken   [2] OCTET STRING OPTIONAL,
        mechListMIC     [3] OCTET STRING OPTIONAL
    }
    """
    componentType = NamedTypes(
        OptionalNamedType(
            'negState', NegState().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 0)
            )
        ),
        OptionalNamedType(
            'supportedMech', MechType().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 1)
            )
        ),
        OptionalNamedType(
            'responseToken', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 2)
            )
        ),
        OptionalNamedType(
            'mechListMIC', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 3)
            )
        )
    )


class NegotiationToken(Choice):
    """
    [RFC-4178] 4.2. Negotiation Tokens

    This is the container used in InitialContextToken and then sent for
    subsequent SPNEGO messages.

    NegotiationToken ::= CHOICE {
        negTokenInit    [0] NegTokenInit,
        negTokenResp    [1] NegTokenResp
    }
    """
    componentType = NamedTypes(
        NamedType(
            'negTokenInit', NegTokenInit().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 0)
            )
        ),
        NamedType(
            'negTokenResp', NegTokenResp().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 1)
            )
        )
    )


class InitialContextToken(Sequence):
    """
    [RFC-2743] 3.1. Mechanism-Independent Token Format

    This section specifies a mechanism-independent level of encapsulating
    representation for the initial token of a GSS-API context establishment
    sequence.

    InitialContextToken ::= [APPLICATION 0] IMPLICIT SEQUENCE {
        thisMech MechType,
        innerContextToken NegotiateToken
    }
    """
    componentType = NamedTypes(
        NamedType(
            'thisMech', MechType()
        ),
        NamedType(
            'innerContextToken', NegotiationToken()
        )
    )
    tagSet = TagSet(
        Sequence.tagSet,
        Tag(tagClassApplication, tagFormatConstructed, 0)
    )

    def __init__(self, **kwargs):
        super(InitialContextToken, self).__init__(**kwargs)
        self['thisMech'] = SPNEGOMechs.SPNEGO


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
