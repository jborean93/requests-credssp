import unittest2 as unittest
import mock
import requests

from ntlm_auth import ntlm, session_security

from requests_credssp import HttpCredSSPAuth
from requests_credssp.exceptions import AuthenticationException, InvalidConfigurationException
from requests_credssp.asn_structures import TSRequest

from tests.expectations import public_key_ts_request, server_pub_key_token
from tests.utils import hex_to_byte

def assert_tlsv1(type):
    assert type == 4

def assert_tlsv1_2(type):
    assert type == 6

def assert_tlsv1_options(options):
    assert options == 0x00000800 | 0x00000200

def assert_ciphers_all(cipher):
    assert cipher == 'ALL'

def mock_unwrap_public_key(signature, encrypted_key):
    return server_pub_key_token

class CredSSPTests(unittest.TestCase):
    def test_auth_mechanism_ntlm(self):
        test_mechanism = 'ntlm'
        actual_object = HttpCredSSPAuth('', '', auth_mechanism=test_mechanism)
        actual = actual_object.context

        assert isinstance(actual, ntlm.Ntlm)

    def test_auth_mechanism_kerberos(self):
        with self.assertRaises(InvalidConfigurationException) as context:
            HttpCredSSPAuth('', '', auth_mechanism='kerberos')

        self.assertTrue('Kerberos auth not yet implemented, please use NTLM instead', context.exception.args)

    def test_auth_mechanism_unknown(self):
        with self.assertRaises(InvalidConfigurationException) as context:
            HttpCredSSPAuth('', '', auth_mechanism='unknown')

        self.assertTrue('Unknown auth mechanism unknown, please specify ntlm', context.exception.args)

    @mock.patch("OpenSSL.SSL.Context.__init__", side_effect=assert_tlsv1_2)
    @mock.patch("OpenSSL.SSL.Context.set_cipher_list", side_effect=assert_ciphers_all)
    def test_tls1_2_option_default(self, tls_version, cipher_assert):
        # The testing is actually happening in the mocking functions
        HttpCredSSPAuth('', '')

    @mock.patch("OpenSSL.SSL.Context.__init__", side_effect=assert_tlsv1_2)
    @mock.patch("OpenSSL.SSL.Context.set_cipher_list", side_effect=assert_ciphers_all)
    def test_tlsv1_2_enabled(self, tls_version, cipher_assert):
        # The testing is actually happening in the mocking functions
        HttpCredSSPAuth('', '', disable_tlsv1_2=False)

    @mock.patch("OpenSSL.SSL.Context.__init__", side_effect=assert_tlsv1)
    @mock.patch("OpenSSL.SSL.Context.set_options", side_effect=assert_tlsv1_options)
    @mock.patch("OpenSSL.SSL.Context.set_cipher_list", side_effect=assert_ciphers_all)
    def test_tlsv1_2_disabled(self, tls_version, tls_options, cipher_assert):
        # The testing is actually happening in the mocking functions
        HttpCredSSPAuth('', '', disable_tlsv1_2=True)

    @mock.patch("ntlm_auth.session_security.SessionSecurity.unwrap", side_effect=mock_unwrap_public_key)
    def test_verify_public_key_good(self, mock_unwrap):
        test_credssp_context = HttpCredSSPAuth('', '')
        test_ntlm_context = ntlm.Ntlm()
        test_ntlm_context.session_security = session_security.SessionSecurity(1, 'key'.encode())
        test_credssp_context.context = test_ntlm_context
        test_ts_request = TSRequest()
        test_ts_request.parse_data(public_key_ts_request)
        test_public_key = hex_to_byte('00') + server_pub_key_token[1:]

        test_credssp_context._verify_public_keys(test_public_key, test_ts_request)

    @mock.patch("ntlm_auth.session_security.SessionSecurity.unwrap", side_effect=mock_unwrap_public_key)
    def test_verify_public_key_invalid(self, mock_unwrap):
        test_credssp_context = HttpCredSSPAuth('', '')
        test_ntlm_context = ntlm.Ntlm()
        test_ntlm_context.session_security = session_security.SessionSecurity(1, 'key'.encode())
        test_credssp_context.context = test_ntlm_context
        test_ts_request = TSRequest()
        test_ts_request.parse_data(public_key_ts_request)

        # Use the wrong first byte to ensure the keys don't match
        test_public_key = hex_to_byte('01') + server_pub_key_token[1:]

        with self.assertRaises(AssertionError) as context:
            test_credssp_context._verify_public_keys(test_public_key, test_ts_request)

        assert context.exception.args[0] == 'Could not verify key sent from the server, possibly man in the middle attack'

    def test_parse_username_with_backslash(self):
        test_username = 'DOMAIN\\USER'
        expected_domain = 'DOMAIN'
        expected_user = 'USER'

        actual_domain, actual_user = HttpCredSSPAuth._parse_username(test_username)
        assert actual_domain == expected_domain
        assert actual_user == expected_user

    def test_parse_username_with_at(self):
        test_username = 'USER@DOMAIN.LOCAL'
        expected_domain = 'DOMAIN.LOCAL'
        expected_user = 'USER'

        actual_domain, actual_user = HttpCredSSPAuth._parse_username(test_username)
        assert actual_domain == expected_domain
        assert actual_user == expected_user

    def test_parse_username_without_domain(self):
        test_username = 'USER'
        expected_domain = '.'
        expected_user = 'USER'

        actual_domain, actual_user = HttpCredSSPAuth._parse_username(test_username)
        assert actual_domain == expected_domain
        assert actual_user == expected_user

    def test_check_credssp_token(self):
        test_request = requests.Request('GET', '')
        test_request.headers['www-authenticate'] = 'CredSSP'

        HttpCredSSPAuth._check_credssp_supported(test_request)

    def test_check_credssp_token_multiple_auths(self):
        test_request = requests.Request('GET', '')
        test_request.headers['www-authenticate'] = 'NTLM, Negotiate, CredSSP'

        HttpCredSSPAuth._check_credssp_supported(test_request)

    def test_check_credssp_token_fail(self):
        test_request = requests.Request('GET', '')
        test_request.headers['www-authenticate'] = 'NTLM, Negotiate'

        with self.assertRaises(AuthenticationException) as context:
            HttpCredSSPAuth._check_credssp_supported(test_request)

        self.assertTrue('The server did not respond with CredSSP as an available auth method', context.exception.args)

    def test_get_credssp_token_success(self):
        test_request = requests.Request('GET', '')
        test_request.headers['www-authenticate'] = 'CredSSP dGVzdA=='

        expected = 'test'.encode()

        actual = HttpCredSSPAuth._get_credssp_token(test_request)

        assert actual == expected

    def test_get_credssp_token_fail_no_token(self):
        test_request = requests.Request('GET', '')
        test_request.headers['www-authenticate'] = 'CredSSP'

        with self.assertRaises(AuthenticationException) as context:
            HttpCredSSPAuth._get_credssp_token(test_request)

        self.assertTrue('The server did not response with a CredSSP token, auth rejected', context.exception.args)

    def test_get_credssp_token_fail_different_auth(self):
        test_request = requests.Request('GET', '')
        test_request.headers['www-authenticate'] = 'NTLM dGVzdA=='

        with self.assertRaises(AuthenticationException) as context:
            HttpCredSSPAuth._get_credssp_token(test_request)

        self.assertTrue('The server did not response with a CredSSP token, auth rejected', context.exception.args)

    def test_set_credssp_token(self):
        test_request = requests.Request('GET', '')

        HttpCredSSPAuth._set_credssp_token(test_request, 'test'.encode())

        assert test_request.headers['Authorization'] == 'CredSSP dGVzdA=='.encode()
