import binascii
import struct
import unittest2 as unittest

from requests_credssp.asn_structures import NegoData, TSRequest, TSCredentials, TSPasswordCreds
from requests_credssp.exceptions import AsnStructureException, NTStatusException
from tests.expectations import *
from tests.utils import hex_to_byte, byte_to_hex

class TestASNStructures(unittest.TestCase):
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
        with self.assertRaises(AsnStructureException) as context:
            actual = TSRequest()
            actual.parse_data(credential_ts_request)
            actual['fake_field']

        assert context.exception.args[0] == 'Illegal field fake_field in ASN.1 structure'

    def test_get_data_with_missing_mandatory_field(self):

        with self.assertRaises(AsnStructureException) as context:
            test_password_creds = TSPasswordCreds()
            test_password_creds['user_name'] = 'test'.encode('utf-16le')
            test_password_creds.get_data()

        assert context.exception.args[0] == 'Cannot get data for mandatory field domainName, value is not set'

    def test_parse_challenge_ts_request(self):
        expected = challenge_token

        actual_ts_request = TSRequest()
        actual_ts_request.parse_data(challenge_ts_request)

        actual = NegoData()
        actual.parse_data(actual_ts_request['nego_tokens'].value)

        assert expected == actual['nego_token'].value

    def test_parse_nego_data_wrong_sequence(self):
        test_data = hex_to_byte('30 05 A5 03 04 01 03')

        with self.assertRaises(AsnStructureException) as context:
            test_nego_data = NegoData()
            test_nego_data.parse_data(test_data)

        assert context.exception.args[0] == 'Expecting sequence (a0) for negoToken, was (a5)'

    def test_parse_nego_data_wrong_type(self):
        test_data = hex_to_byte('30 05 A0 03 02 01 03')

        with self.assertRaises(AsnStructureException) as context:
            test_nego_data = NegoData()
            test_nego_data.parse_data(test_data)

        assert context.exception.args[0] == 'Expecting negoToken type to be (4), was (2)'

    def test_parse_nego_data_wrong_structure_type(self):
        test_data = hex_to_byte('31 05 A0 03 04 01 03')

        with self.assertRaises(AsnStructureException) as context:
            test_nego_data = NegoData()
            test_nego_data.parse_data(test_data)

        assert context.exception.args[0] == 'Expecting NegoData type to be (30), was (31)'

    def test_parse_public_key(self):
        expected = server_pub_key_token

        actual = TSRequest()
        actual.parse_data(public_key_ts_request)

        assert expected == actual['pub_key_auth'].value

    def test_parse_ts_request_wrong_type(self):
        test_data = hex_to_byte('A0 00 00 00 00')

        with self.assertRaises(AsnStructureException) as context:
            test_ts_request = TSRequest()
            test_ts_request.parse_data(test_data)

        assert context.exception.args[0] == 'Expecting TSRequest type to be (30), was (a0)'

    def test_check_error_code_version_2_none(self):
        test_ts_request = TSRequest()
        test_ts_request.parse_data(challenge_ts_request)
        test_ts_request.check_error_code()

        assert test_ts_request['error_code'].value == None

    def test_check_error_code_version_3_none(self):
        test_data = utils.hex_to_byte('30 09 A0 03 02 01 03')

        test_ts_request = TSRequest()
        test_ts_request.parse_data(test_data)
        test_ts_request.check_error_code()

        assert test_ts_request['error_code'].value == None

    def test_check_error_code_logon_failure(self):
        test_data = hex_to_byte('30 13 A0 03 02 01 03 A4 06 02 04 C0 00 00 6D')

        with self.assertRaises(NTStatusException) as context:
            test_ts_request = TSRequest()
            test_ts_request.parse_data(test_data)
            test_ts_request.check_error_code()

        assert context.exception.args[0] == 'STATUS_LOGON_FAILURE - c000006d'

    def test_check_error_code_undefinied(self):
        test_data = hex_to_byte('30 13 A0 03 02 01 03 A4 06 02 04 C0 00 00 6E')

        with self.assertRaises(NTStatusException) as context:
            test_ts_request = TSRequest()
            test_ts_request.parse_data(test_data)
            test_ts_request.check_error_code()

        assert context.exception.args[0] == 'NTSTATUS error: Not Defined c000006e'
