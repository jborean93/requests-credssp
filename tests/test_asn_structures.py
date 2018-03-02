import struct

import pytest

from requests_credssp.asn_structures import NegoData, TSRequest, \
    TSCredentials, TSPasswordCreds
from requests_credssp.exceptions import AsnStructureException, \
    NTStatusException

from tests.expectations import *


class TestASNStructures(object):
    def test_create_negotiate_nego_data(self):
        expected = negotiate_nego_data

        actual = NegoData()
        actual['nego_token'].value = negotiate_token

        assert expected == actual.get_data()

    def test_create_negotiate_ts_request(self):
        expected = negotiate_ts_request

        actual_nego_data = NegoData()
        actual_nego_data['nego_token'].value = negotiate_token
        actual = TSRequest()
        actual['nego_tokens'].value = actual_nego_data.get_data()

        assert expected == actual.get_data()

    def test_create_authenticate_nego_data(self):
        expected = auth_nego_data

        actual = NegoData()
        actual['nego_token'].value = auth_token

        assert expected == actual.get_data()

    def test_create_authenticate_ts_request(self):
        expected = auth_ts_request

        actual_nego_data = NegoData()
        actual_nego_data['nego_token'].value = auth_token

        actual = TSRequest()
        actual['nego_tokens'].value = actual_nego_data.get_data()
        actual['pub_key_auth'].value = pub_key_token

        assert expected == actual.get_data()

    def test_create_ts_password_credentials(self):
        expected = credential_ts_password_creds

        actual = TSPasswordCreds()
        actual['domain_name'].value = domain
        actual['user_name'].value = user
        actual['password'].value = password

        assert expected == actual.get_data()

    def test_create_ts_credentials(self):
        expected = credential_ts_credentials

        actual_creds = TSPasswordCreds()
        actual_creds['domain_name'].value = domain
        actual_creds['user_name'].value = user
        actual_creds['password'].value = password

        actual = TSCredentials()
        actual['cred_type'].value = struct.pack('B', 1)
        actual['credentials'].value = actual_creds.get_data()

        assert expected == actual.get_data()

    def test_create_credential_ts_request(self):
        expected = credential_ts_request

        actual = TSRequest()
        actual['auth_info'].value = credentials_encrypted_password_creds

        assert expected == actual.get_data()

    def test_get_empty_field(self):
        with pytest.raises(AsnStructureException) as exc:
            actual = TSRequest()
            actual.parse_data(credential_ts_request)
            actual['fake_field']

        assert str(exc.value) == 'Illegal field fake_field in ASN.1 structure'

    def test_get_data_with_missing_mandatory_field(self):
        with pytest.raises(AsnStructureException) as exc:
            test_password_creds = TSPasswordCreds()
            test_password_creds['user_name'] = 'test'.encode('utf-16le')
            test_password_creds.get_data()

        assert str(exc.value) == 'Cannot get data for mandatory field ' \
                                 'domainName, value is not set'

    def test_parse_challenge_ts_request(self):
        expected = challenge_token

        actual_ts_request = TSRequest()
        actual_ts_request.parse_data(challenge_ts_request)

        actual = NegoData()
        actual.parse_data(actual_ts_request['nego_tokens'].value)

        assert expected == actual['nego_token'].value

    def test_parse_ts_request_invalid_sequence(self):
        test_data = b'\x30\x13\xA0\x03\x02\x01\x03\xA6' \
                    b'\x03\x02\x01\x01'

        with pytest.raises(AsnStructureException) as exc:
            test_ts_request = TSRequest()
            test_ts_request.parse_data(test_data)

        assert str(exc.value) == 'Unknown sequence byte (a6) in sequence'

    def test_parse_nego_data_wrong_sequence(self):
        test_data = b'\x30\x05\xA5\x03\x04\x01\x03'

        with pytest.raises(AsnStructureException) as exc:
            test_nego_data = NegoData()
            test_nego_data.parse_data(test_data)

        assert str(exc.value) == \
            'Expecting sequence (a0) for negoToken, was (a5)'

    def test_parse_nego_data_wrong_type(self):
        test_data = b'\x30\x05\xA0\x03\x02\x01\x03'

        with pytest.raises(AsnStructureException) as exc:
            test_nego_data = NegoData()
            test_nego_data.parse_data(test_data)

        assert str(exc.value) == 'Expecting negoToken type to be (4), was (2)'

    def test_parse_nego_data_wrong_structure_type(self):
        test_data = b'\x31\x05\xA0\x03\x04\x01\x03'

        with pytest.raises(AsnStructureException) as exc:
            test_nego_data = NegoData()
            test_nego_data.parse_data(test_data)

        assert str(exc.value) == 'Expecting NegoData type to be (30), was (31)'

    def test_parse_public_key(self):
        expected = server_pub_key_token

        actual = TSRequest()
        actual.parse_data(public_key_ts_request)

        assert expected == actual['pub_key_auth'].value

    def test_parse_ts_request_wrong_type(self):
        test_data = b'\xA0\x00\x00\x00\x00'

        with pytest.raises(AsnStructureException) as exc:
            test_ts_request = TSRequest()
            test_ts_request.parse_data(test_data)

        assert str(exc.value) == \
            'Expecting TSRequest type to be (30), was (a0)'

    def test_check_error_code_version_2_none(self):
        test_ts_request = TSRequest()
        test_ts_request.parse_data(challenge_ts_request)
        test_ts_request.check_error_code()

        assert test_ts_request['error_code'].value is None

    def test_check_error_code_version_3_none(self):
        test_data = b'\x30\x09\xA0\x03\x02\x01\x03'

        test_ts_request = TSRequest()
        test_ts_request.parse_data(test_data)
        test_ts_request.check_error_code()

        assert test_ts_request['error_code'].value is None

    def test_check_error_code_logon_failure(self):
        expected_byte = b'c000006d'
        test_data = b'\x30\x13\xA0\x03\x02\x01\x03\xA4' \
                    b'\x06\x02\x04\xC0\x00\x00\x6D'

        with pytest.raises(NTStatusException) as exc:
            test_ts_request = TSRequest()
            test_ts_request.parse_data(test_data)
            test_ts_request.check_error_code()

        assert str(exc.value) == 'STATUS_LOGON_FAILURE - %s' % expected_byte

    def test_check_error_code_undefinied(self):
        expected_byte = b'c000006e'
        test_data = b'\x30\x13\xA0\x03\x02\x01\x03\xA4' \
                    b'\x06\x02\x04\xC0\x00\x00\x6E'

        with pytest.raises(NTStatusException) as exc:
            test_ts_request = TSRequest()
            test_ts_request.parse_data(test_data)
            test_ts_request.check_error_code()

        assert str(exc.value) == \
            'NTSTATUS error: Not Defined %s' % expected_byte
