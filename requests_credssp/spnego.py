import base64
import gssapi

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse


from requests_credssp.asn_structures import TSRequest, NegoData


from pyasn1.type.char import GeneralString
from pyasn1.type.constraint import SingleValueConstraint
from pyasn1.type.univ import BitString, Choice, Enumerated, ObjectIdentifier, \
    OctetString, Sequence, SequenceOf
from pyasn1.type.namedtype import NamedType, NamedTypes, OptionalNamedType
from pyasn1.type.namedval import NamedValues
from pyasn1.type.tag import Tag, tagClassApplication, tagClassContext, \
    tagFormatConstructed, tagFormatSimple, tagClassUniversal, TagSet



class SpnegoContext(object):
    def __init__(self, response, username, password):
        """
        Creates a SPNEGO context used to authenticate the client.

        :param url: The URL used in the HTTP request, this is used to get the
            hostname for the SPN
        :param username: The username to authenticate with, if None then the
            default credential stored is used
        :param password: The password to authenticate with, if None then the
            username specified must already exist in the credential cache
        """
        self.response = response
        self.hostname = urlparse(response.url).hostname
        #self.hostname = "192.168.56.10"
        server_spn = "HTTP/%s@DOMAIN.LOCAL" % self.hostname
        self.spn = gssapi.Name(server_spn,
                               name_type=gssapi.NameType.kerberos_principal)
        self.username = username
        self.password = password

        user_spn = gssapi.Name(base=username,
                               name_type=gssapi.NameType.kerberos_principal)
        creds = gssapi.Credentials(name=user_spn, usage='initiate')
        self.context = gssapi.SecurityContext(name=self.spn, creds=creds,
                                              usage='initiate')

    def negotiate_auth_mech(self, parent, **kwargs):
        import struct
        import binascii
        from pyasn1.codec.der.encoder import encoder
        from pyasn1.codec.der.decoder import decoder


        token = self.context.step()

        #mech_types = MechTypeList()
        #mech_types.setComponents(
        #    MechTypes.KRB5,
        #    MechTypes.MS_KRB5,
        #    MechTypes.NTLMSSP
        #)

        #mech_types = decoder.decode(a, asn1Spec=MechTypeList())

        #neg_token_init = NegTokenInit()
        #neg_token_init['mechToken'] = token
        #neg_token_init['mechTypes'] = mech_types
        #neg_token_init['mechTypes'] = [ MechTypes.KRB5, MechTypes.MS_KRB5, MechTypes.NTLMSSP ]
        #neg_token_init.setComponentByName('mechTypes', mech_types)
        #neg_token_init.setComponentByName('mechTypes', b)
        #neg_token_init['mechTypes'] = b


        #negotiate_token = NegotiateToken()
        #negotiate_token['negTokenInit'] = neg_token_init

        #initial_context_token = InitialContextToken()
        #initial_context_token['thisMech'] = ObjectIdentifier('1.3.6.1.5.5.2')
        #initial_context_token['innerContextToken'] = negotiate_token

        mech_types = binascii.unhexlify("A024302206092a864886f71201020206092a864882f712010202060a2b06010401823702020a")
        token_length = struct.pack(">H", len(token))
        kerb_token = b"\xa2\x82" + struct.pack(">H", len(token) + len(token_length) + 2) + b"\x04\x82" + token_length + token
        neg_token = b"" + mech_types + kerb_token

        initial_context_token = b"\x30\x82" + struct.pack(">H", len(neg_token)) + neg_token

        spnego_oid = b"\x06\x06\x2B\x06\x01\x05\x05\x02"
        gss_blob = b"\xa0\x82" + struct.pack(">H", len(initial_context_token)) + initial_context_token
        gss_token = b"\x60\x82" + struct.pack(">H", len(spnego_oid) + len(gss_blob)) + spnego_oid + gss_blob

        #spnego_token = encoder.encode(initial_context_token)
        spnego_token = gss_token

        nego_data = NegoData()
        nego_data['nego_token'].value = spnego_token

        ts_request = TSRequest()
        ts_request['nego_tokens'].value = nego_data.get_data()
        credssp_token = parent.wrap(ts_request.get_data())

        request = self.response.request.copy()
        request.headers['Authorization'] = b"CredSSP %s"\
                                           % base64.b64encode(credssp_token)

        response = self.response.connection.send(request, **kwargs)
        response.content
        response.raw.release_conn()

        response_token = parent._get_credssp_token(response)
        response_token_data = parent.unwrap(response_token)

        ts_request = TSRequest()
        ts_request.parse_data(response_token_data)
        ts_request.check_error_code()

        nego_data = NegoData()
        nego_data.parse_data(ts_request['nego_tokens'].value)
        in_token = nego_data['nego_token'].value

        a = ""

        #response = response.connection.send(auth_request, **kwargs)
        #response.content
        #response.raw.release_conn()
        #response_token = self._get_credssp_token(response)
        #response_token_data = self.unwrap(response_token)

        #ts_request = TSRequest()
        #ts_request.parse_data(response_token_data)
        #ts_request.check_error_code()

        #nego_data = NegoData()
        #nego_data.parse_data(ts_request['nego_tokens'].value)
        #in_token = nego_data['nego_token'].value
        #out_token = context.step(token=in_token)







class MechTypes(object):
    # Currently only NTLMSSP is supported, with the aim to support Kerberos
    MS_KRB5 = ObjectIdentifier('1.2.840.48018.1.2.2')
    KRB5 = ObjectIdentifier('1.2.840.113554.1.2.2')
    KRB5_U2U = ObjectIdentifier('1.2.840.113554.1.2.2.3')
    NEGOEX = ObjectIdentifier('1.3.6.1.4.1.311.2.2.30')
    NTLMSSP = ObjectIdentifier('1.3.6.1.4.1.311.2.2.10')


class MechType(ObjectIdentifier):
    """
    [RFC-4178]

    4.1 Mechanism Types
    OID represents one GSS-API mechanism according to RFC-2743.

    MechType ::= OBJECT IDENTIFIER
    """
    pass


class MechTypeList(SequenceOf):
    """
    [RFC-4178]

    4.1 Mechanism Types
    List of MechTypes

    MechTypeList ::= SEQUENCE OF MechType
    """
    componentType = ObjectIdentifier()


class ContextFlags(BitString):
    """
    [RFC-41178]

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


class NegStat(Enumerated):
    """
    [RFC-41178]

    NegState ::= ENUMERATED {
        accept-completed (0),
        accept-incomplete (1),
        reject (2),
        request-mic (3)
    }
    """
    namedValues = NamedValues(
        ('accept-complete', 0),
        ('accept-incomplete', 1),
        ('reject', 2),
        ('request-mic', 3)
    )
    subtypeSpec = Enumerated.subtypeSpec + SingleValueConstraint(0, 1, 2, 3)


class NegHints(Sequence):
    """
    [MS-SPNG] v14.0 2017-09-15

    2.2.1 NegTokenInit2
    NegHints is an extension of NegTokenInit.

    NegHints ::= SEQUENCE {
        hintName[0] GeneralString OPTIONAL,
        hintAddress[1] OCTET STRING OPTIONAL
    }
    """
    componentType = NamedTypes(
        OptionalNamedType(
            'hintName', GeneralString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 0)
            )
        ),
        OptionalNamedType(
            'hintAddress', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 1)
            )
        )
    )


class NegTokenInit(Sequence):
    """
    [RFC-4117]

    NegTokenInit ::= SEQUENCE {
        mechTypes [0] MechTypeList,
        regFlags [1] ContextFlags OPTIONAL,
        mechToken [2] OCTET STRING OPTIONAL,
        mechListMIC [3] OCTER STRING OPTIONAL,
        ...
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


class NegTokenInit2(Sequence):
    """
    [MS-SPNG] v14.0 2017-09-15

    2.2.1 NegTokenInit2
    NegTokenInit2 is the message structure that extends NegTokenInit with a
    negotiation hints (negHints) field. On a server initiated SPNEGO process,
    it sends negTokenInit2 message instead of just the plain NegTokenInit.

    NegTokenInit2 ::= SEQUENCE {
        mechTypes [0] MechTypeList OPTIONAL,
        reqFlags [1] ContextFlags OPTIONAL,
        mechToken [2] OCTET STRING OPTIONAL,
        negHints [3] NegHints OPTIONAL,
        mechListMIC [4] OCTET STRING OPTIONAL,
        ...
    }
    """
    componentType = NamedTypes(
        OptionalNamedType(
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
            'negHints', NegHints().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 3)
            )
        ),
        OptionalNamedType(
            'mechListMIC', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 4)
            )
        ),
    )


class NegTokenResp(Sequence):
    """
    [RFC-41178]

    4.2.2 negTokenResp
    The response message for NegTokenInit.

    NegTokenResp ::= SEQUENCE {
        negStat [0] NegState OPTIONAL,
        supportedMech [1] MechType OPTIONAL,
        responseToken [2] OCTET STRING OPTIONAL,
        mechListMIC {3] OCTET STRING OPTIONAL,
        ...
    }
    """
    componentType = NamedTypes(
        OptionalNamedType(
            'negStat', NegStat().subtype(
                explicitTag=Tag(tagClassContext, tagFormatConstructed, 0)
            )
        ),
        OptionalNamedType(
            'supportedMech', ObjectIdentifier().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 1)
            )
        ),
        OptionalNamedType(
            'responseToken', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 2)
            )
        ),
        OptionalNamedType(
            'mechListMIC', OctetString().subtype(
                explicitTag=Tag(tagClassContext, tagFormatSimple, 3)
            )
        )
    )


class NegotiateToken(Choice):
    """
    [RFC-41178]

    NegotiateToken ::= CHOICE {
        negTokenInit [0] NegTokenInit,
        negTokenResp [1] NegTokenResp
    }
    """
    componentType = NamedTypes(
        NamedType(
            'negTokenInit', NegTokenInit2().subtype(
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
    [RFC-2743]

    3.1. Mechanism-Independent Token Format
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
            'thisMech', ObjectIdentifier()
        ),
        NamedType(
            'innerContextToken', NegotiateToken()
        )
    )
    tagSet = TagSet(
        Sequence.tagSet,
        Tag(tagClassApplication, tagFormatConstructed, 0),
    )
