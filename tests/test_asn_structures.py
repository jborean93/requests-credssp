import pytest

from pyasn1.codec.der import decoder, encoder

from requests_credssp.asn_structures import InitialContextToken, NegoData, \
    NegoToken, NegTokenInit, NegTokenResp, NegotiationToken, SPNEGOMechs, \
    SPNEGONegState, TSRequest, TSCredentials, TSPasswordCreds
from requests_credssp.exceptions import NtStatusCodes, NTStatusException


class TestSPNEGOMechs(object):

    def test_spnego(self):
        expected = b"\x06\x06" \
                   b"\x2b\x06\x01\x05\x05\x02"
        actual = encoder.encode(SPNEGOMechs.SPNEGO)
        assert actual == expected

    def test_krb5(self):
        expected = b"\x06\x09" \
                   b"\x2a\x86\x48\x86\xf7\x12\x01\x02" \
                   b"\x02"
        actual = encoder.encode(SPNEGOMechs.KRB5)
        assert actual == expected

    def test_ntlmssp(self):
        expected = b"\x06\x0a" \
                   b"\x2b\x06\x01\x04\x01\x82\x37\x02" \
                   b"\x02\x0a"
        actual = encoder.encode(SPNEGOMechs.NTLMSSP)
        assert actual == expected


class TestNegTokenInit(object):

    def test_create(self):
        expected = b"\x30\x23" \
                   b"\xa0\x19" \
                   b"\x30\x17" \
                   b"\x06\x09" \
                   b"\x2a\x86\x48\x86\xf7\x12\x01\x02" \
                   b"\x02" \
                   b"\x06\x0a" \
                   b"\x2b\x06\x01\x04\x01\x82\x37\x02" \
                   b"\x02\x0a" \
                   b"\xa2\x06" \
                   b"\x04\x04" \
                   b"\x01\x02\x03\x04"
        neg_token_init = NegTokenInit()
        neg_token_init['mechTypes'].append(SPNEGOMechs.KRB5)
        neg_token_init['mechTypes'].append(SPNEGOMechs.NTLMSSP)
        neg_token_init['mechToken'] = b"\x01\x02\x03\x04"
        actual = encoder.encode(neg_token_init)
        assert actual == expected

    def test_parse(self):
        data = b"\x30\x23" \
               b"\xa0\x19" \
               b"\x30\x17" \
               b"\x06\x09" \
               b"\x2a\x86\x48\x86\xf7\x12\x01\x02" \
               b"\x02" \
               b"\x06\x0a" \
               b"\x2b\x06\x01\x04\x01\x82\x37\x02" \
               b"\x02\x0a" \
               b"\xa2\x06" \
               b"\x04\x04" \
               b"\x01\x02\x03\x04"
        actual, remaining = decoder.decode(data, asn1Spec=NegTokenInit())
        assert remaining == b""
        assert len(actual['mechTypes']) == 2
        assert actual['mechTypes'][0] == SPNEGOMechs.KRB5
        assert actual['mechTypes'][1] == SPNEGOMechs.NTLMSSP
        assert actual['mechToken'] == b"\x01\x02\x03\x04"


class TestNegTokenResp(object):

    def test_create(self):
        expected = b"\x30\x15" \
                   b"\xa0\x03" \
                   b"\x0a\x01" \
                   b"\x01" \
                   b"\xa2\x06" \
                   b"\x04\x04" \
                   b"\x05\x06\x07\x08" \
                   b"\xa3\x06" \
                   b"\x04\x04" \
                   b"\x09\x0a\x0b\x0c"
        neg_token_resp = NegTokenResp()
        neg_token_resp['negState'] = SPNEGONegState.ACCEPT_INCOMPLETE
        neg_token_resp['responseToken'] = b"\x05\x06\x07\x08"
        neg_token_resp['mechListMIC'] = b"\x09\x0a\x0b\x0c"
        actual = encoder.encode(neg_token_resp)
        assert actual == expected

    def test_parse(self):
        data = b"\x30\x1f" \
               b"\xa0\x03" \
               b"\x0a\x01" \
               b"\x01" \
               b"\xa1\x08" \
               b"\x06\x06" \
               b"\x2b\x06\x01\x05\x05\x02" \
               b"\xa2\x06" \
               b"\x04\x04" \
               b"\x05\x06\x07\x08" \
               b"\xa3\x06" \
               b"\x04\x04" \
               b"\x09\x0a\x0b\x0c"
        actual, remaining = decoder.decode(data, asn1Spec=NegTokenResp())
        assert remaining == b""
        assert actual['negState'] == SPNEGONegState.ACCEPT_INCOMPLETE
        assert actual['supportedMech'] == SPNEGOMechs.SPNEGO
        assert actual['responseToken'] == b"\x05\x06\x07\x08"
        assert actual['mechListMIC'] == b"\x09\x0a\x0b\x0c"


class TestNegotiationToken(object):

    def test_create_init(self):
        expected = b"\xa0\x1a" \
                   b"\x30\x18" \
                   b"\xa0\x0e" \
                   b"\x30\x0c" \
                   b"\x06\x0a" \
                   b"\x2b\x06\x01\x04\x01\x82\x37\x02" \
                   b"\x02\x0a" \
                   b"\xa2\x06" \
                   b"\x04\x04" \
                   b"\x01\x02\x03\x04"
        negotiation_token = NegotiationToken()
        negotiation_token['negTokenInit']['mechTypes'].append(
            SPNEGOMechs.NTLMSSP
        )
        negotiation_token['negTokenInit']['mechToken'] = b"\x01\x02\x03\x04"
        actual = encoder.encode(negotiation_token)
        assert actual == expected

    def test_create_resp(self):
        expected = b"\xa1\x0f" \
                   b"\x30\x0d" \
                   b"\xa0\x03" \
                   b"\x0a\x01" \
                   b"\x00" \
                   b"\xa2\x06" \
                   b"\x04\x04" \
                   b"\x01\x02\x03\x04"
        negotiation_token = NegotiationToken()
        negotiation_token['negTokenResp']['negState'] = \
            SPNEGONegState.ACCEPT_COMPLETE
        negotiation_token['negTokenResp']['responseToken'] = \
            b"\x01\x02\x03\x04"
        actual = encoder.encode(negotiation_token)
        assert actual == expected

    def test_parse_init(self):
        data = b"\xa0\x1a" \
               b"\x30\x18" \
               b"\xa0\x0e" \
               b"\x30\x0c" \
               b"\x06\x0a" \
               b"\x2b\x06\x01\x04\x01\x82\x37\x02" \
               b"\x02\x0a" \
               b"\xa2\x06" \
               b"\x04\x04" \
               b"\x01\x02\x03\x04"
        actual, remaining = decoder.decode(data, asn1Spec=NegotiationToken())
        assert remaining == b""
        mech_types = actual['negTokenInit']['mechTypes']
        assert len(mech_types) == 1
        assert mech_types[0] == SPNEGOMechs.NTLMSSP
        assert actual['negTokenInit']['mechToken'] == b"\x01\x02\x03\x04"

    def test_parse_resp(self):
        data = b"\xa1\x0f" \
               b"\x30\x0d" \
               b"\xa0\x03" \
               b"\x0a\x01" \
               b"\x00" \
               b"\xa2\x06" \
               b"\x04\x04" \
               b"\x01\x02\x03\x04"
        actual, remaining = decoder.decode(data, asn1Spec=NegotiationToken())
        assert remaining == b""
        assert actual['negTokenResp']['negState'] == \
            SPNEGONegState.ACCEPT_COMPLETE
        assert actual['negTokenResp']['responseToken'] == b"\x01\x02\x03\x04"


class TestInitialContextToken(object):

    def test_create(self):
        expected = b"\x60\x24" \
                   b"\x06\x06" \
                   b"\x2b\x06\x01\x05\x05\x02" \
                   b"\xa0\x1a" \
                   b"\x30\x18" \
                   b"\xa0\x0e" \
                   b"\x30\x0c" \
                   b"\x06\x0a" \
                   b"\x2b\x06\x01\x04\x01\x82\x37\x02" \
                   b"\x02\x0a" \
                   b"\xa2\x06" \
                   b"\x04\x04" \
                   b"\x01\x02\x03\x04"
        token = InitialContextToken()
        token['innerContextToken']['negTokenInit']['mechTypes'].append(
            SPNEGOMechs.NTLMSSP
        )
        token['innerContextToken']['negTokenInit']['mechToken'] = \
            b"\x01\x02\x03\x04"
        actual = encoder.encode(token)
        assert actual == expected

    def test_parse(self):
        data = b"\x60\x24" \
               b"\x06\x06" \
               b"\x2b\x06\x01\x05\x05\x02" \
               b"\xa0\x1a" \
               b"\x30\x18" \
               b"\xa0\x0e" \
               b"\x30\x0c" \
               b"\x06\x0a" \
               b"\x2b\x06\x01\x04\x01\x82\x37\x02" \
               b"\x02\x0a" \
               b"\xa2\x06" \
               b"\x04\x04" \
               b"\x01\x02\x03\x04"
        actual, remaining = \
            decoder.decode(data, asn1Spec=InitialContextToken())
        assert remaining == b""
        assert actual['thisMech'] == SPNEGOMechs.SPNEGO
        mech_types = actual['innerContextToken']['negTokenInit']['mechTypes']
        assert len(mech_types) == 1
        assert mech_types[0] == SPNEGOMechs.NTLMSSP
        assert actual['innerContextToken']['negTokenInit']['mechToken'] == \
            b"\x01\x02\x03\x04"


class TestNegoToken(object):

    def test_create(self):
        expected = b"\x30\x08" \
                   b"\xa0\x06" \
                   b"\x04\x04" \
                   b"\x05\x06\x07\x08"
        nego_token = NegoToken()
        nego_token['negoToken'] = b"\x05\x06\x07\x08"
        actual = encoder.encode(nego_token)
        assert actual == expected

    def test_parse(self):
        data = b"\x30\x08" \
               b"\xa0\x06" \
               b"\x04\x04" \
               b"\x05\x06\x07\x08"
        actual, remaining = decoder.decode(data, asn1Spec=NegoToken())
        assert remaining == b""
        assert actual['negoToken'] == b"\x05\x06\x07\x08"


class TestNegoData(object):

    def test_create(self):
        expected = b"\x30\x0a" \
                   b"\x30\x08" \
                   b"\xa0\x06" \
                   b"\x04\x04" \
                   b"\x01\x02\x03\x04"
        nego_data = NegoData()
        nego_data[0]['negoToken'] = b"\x01\x02\x03\x04"
        actual = encoder.encode(nego_data)
        assert actual == expected

    def test_parse(self):
        data = b"\x30\x0a" \
               b"\x30\x08" \
               b"\xa0\x06" \
               b"\x04\x04" \
               b"\x01\x02\x03\x04"
        actual, remaining = decoder.decode(data, asn1Spec=NegoData())
        assert remaining == b""
        assert len(actual) == 1
        assert actual[0]['negoToken'] == b"\x01\x02\x03\x04"


class TestTSRequest(object):

    def test_create(self):
        expected = b"\x30\x30" \
                   b"\xa0\x03" \
                   b"\x02\x01" \
                   b"\x06" \
                   b"\xa1\x0c" \
                   b"\x30\x0a" \
                   b"\x30\x08" \
                   b"\xa0\x06" \
                   b"\x04\x04" \
                   b"\xaa\xbb\xcc\xdd" \
                   b"\xa2\x06" \
                   b"\x04\x04" \
                   b"\x01\x02\x03\x04" \
                   b"\xa3\x06" \
                   b"\x04\x04" \
                   b"\x05\x06\x07\x08" \
                   b"\xa4\x03" \
                   b"\x02\x01" \
                   b"\x02" \
                   b"\xa5\x06" \
                   b"\x04\x04" \
                   b"\x09\x0a\x0b\x0d"
        ts_request = TSRequest()
        nego_token = NegoToken()
        nego_token['negoToken'] = b"\xaa\xbb\xcc\xdd"
        ts_request['negoTokens'].append(nego_token)
        ts_request['authInfo'] = b"\x01\x02\x03\x04"
        ts_request['pubKeyAuth'] = b"\x05\x06\x07\x08"
        ts_request['errorCode'] = 2
        ts_request['clientNonce'] = b"\x09\x0a\x0b\x0d"
        actual = encoder.encode(ts_request)
        assert actual == expected

    def test_parse(self):
        data = b"\x30\x30" \
               b"\xa0\x03" \
               b"\x02\x01" \
               b"\x06" \
               b"\xa1\x0c" \
               b"\x30\x0a" \
               b"\x30\x08" \
               b"\xa0\x06" \
               b"\x04\x04" \
               b"\xaa\xbb\xcc\xdd" \
               b"\xa2\x06" \
               b"\x04\x04" \
               b"\x01\x02\x03\x04" \
               b"\xa3\x06" \
               b"\x04\x04" \
               b"\x05\x06\x07\x08" \
               b"\xa4\x03" \
               b"\x02\x01" \
               b"\x02" \
               b"\xa5\x06" \
               b"\x04\x04" \
               b"\x09\x0a\x0b\x0d"
        actual, remaining = decoder.decode(data, asn1Spec=TSRequest())
        assert remaining == b""
        assert actual['version'] == 6
        assert len(actual['negoTokens']) == 1
        assert actual['negoTokens'][0]['negoToken'] == b"\xaa\xbb\xcc\xdd"
        assert actual['authInfo'] == b"\x01\x02\x03\x04"
        assert actual['pubKeyAuth'] == b"\x05\x06\x07\x08"
        assert actual['errorCode'] == 2
        assert actual['clientNonce'] == b"\x09\x0a\x0b\x0d"

    def test_check_error_no_code_set(self):
        ts_request = TSRequest()
        ts_request.check_error_code()

    def test_check_error_code_success(self):
        ts_request = TSRequest()
        ts_request['errorCode'] = NtStatusCodes.STATUS_SUCCESS
        ts_request.check_error_code()

    def test_check_error_code_fail(self):
        ts_request = TSRequest()
        ts_request['errorCode'] = NtStatusCodes.STATUS_LOGON_FAILURE
        with pytest.raises(NTStatusException) as exc:
            ts_request.check_error_code()
        assert str(exc.value) == "Received error status from the server: " \
                                 "(3221225581) STATUS_LOGON_FAILURE 0xc000006d"


class TestTSCredentials(object):

    def test_create(self):
        expected = b"\x30\x0d" \
                   b"\xa0\x03" \
                   b"\x02\x01" \
                   b"\x01" \
                   b"\xa1\x06" \
                   b"\x04\x04" \
                   b"\x01\x02\x03\x04"
        ts_credentials = TSCredentials()
        ts_credentials['credType'] = 1
        ts_credentials['credentials'] = b"\x01\x02\x03\x04"
        actual = encoder.encode(ts_credentials)
        assert actual == expected

    def test_parse(self):
        data = b"\x30\x0d" \
               b"\xa0\x03" \
               b"\x02\x01" \
               b"\x01" \
               b"\xa1\x06" \
               b"\x04\x04" \
               b"\x01\x02\x03\x04"
        actual, remaining = decoder.decode(data, asn1Spec=TSCredentials())
        assert remaining == b""
        assert actual['credType'] == 1
        assert actual['credentials'] == b"\x01\x02\x03\x04"


class TestTSPasswordCreds(object):

    def test_create(self):
        expected = b"\x30\x38" \
                   b"\xa0\x0e" \
                   b"\x04\x0c" \
                   b"\x64\x00\x6f\x00\x6d\x00\x61\x00" \
                   b"\x69\x00\x6e\x00" \
                   b"\xa1\x12" \
                   b"\x04\x10" \
                   b"\x75\x00\x73\x00\x65\x00\x72\x00" \
                   b"\x6e\x00\x61\x00\x6d\x00\x65\x00" \
                   b"\xa2\x12" \
                   b"\x04\x10" \
                   b"\x70\x00\x61\x00\x73\x00\x73\x00" \
                   b"\x77\x00\x6f\x00\x72\x00\x64\x00"
        ts_password_creds = TSPasswordCreds()
        ts_password_creds['domainName'] = "domain".encode('utf-16-le')
        ts_password_creds['userName'] = "username".encode('utf-16-le')
        ts_password_creds['password'] = "password".encode('utf-16-le')
        actual = encoder.encode(ts_password_creds)
        assert actual == expected

    def test_parse(self):
        data = b"\x30\x38" \
               b"\xa0\x0e" \
               b"\x04\x0c" \
               b"\x64\x00\x6f\x00\x6d\x00\x61\x00" \
               b"\x69\x00\x6e\x00" \
               b"\xa1\x12" \
               b"\x04\x10" \
               b"\x75\x00\x73\x00\x65\x00\x72\x00" \
               b"\x6e\x00\x61\x00\x6d\x00\x65\x00" \
               b"\xa2\x12" \
               b"\x04\x10" \
               b"\x70\x00\x61\x00\x73\x00\x73\x00" \
               b"\x77\x00\x6f\x00\x72\x00\x64\x00"
        actual, remaining = decoder.decode(data, asn1Spec=TSPasswordCreds())
        assert remaining == b""
        assert isinstance(actual, TSPasswordCreds)
        assert actual['domainName'] == "domain".encode('utf-16-le')
        assert actual['userName'] == "username".encode('utf-16-le')
        assert actual['password'] == "password".encode('utf-16-le')
