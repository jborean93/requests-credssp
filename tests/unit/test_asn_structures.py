import struct
import unittest2 as unittest

from requests_credssp.asn_structures import NegoData, TSRequest, TSCredentials, TSPasswordCreds
from tests.expectations import *

class TestCreateASNStructures(unittest.TestCase):
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


class TestParseASNStructures(unittest.TestCase):
    def test_parse_challenge_ts_request(self):
        expected = challenge_token

        actual_ts_request = TSRequest()
        actual_ts_request.parse_data(challenge_ts_request)

        actual = NegoData()
        actual.parse_data(actual_ts_request['nego_tokens'].value)

        assert expected == actual['nego_token'].value

    def test_parse_challenge_nego_data(self):
        expected = challenge_token

        actual = NegoData()
        actual.parse_data(challenge_nego_data)

        assert expected == actual['nego_token'].value

    def test_parse_public_key(self):
        expected = server_pub_key_token

        actual = TSRequest()
        actual.parse_data(public_key_ts_request)

        assert expected == actual['pub_key_auth'].value
