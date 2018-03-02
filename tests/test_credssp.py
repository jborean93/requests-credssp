import os
import re
import requests
import struct
import warnings

import pytest

from xml.etree import ElementTree as ET

from requests_credssp import HttpCredSSPAuth
from requests_credssp.credssp import NTLMContext
from requests_credssp.exceptions import AuthenticationException
from requests_credssp.asn_structures import TSRequest

from tests.expectations import public_key_ts_request, server_pub_key_token


class TestHttpCredSSPAuth(object):

    def test_auth_mechanism_ntlm(self):
        test_mechanism = 'ntlm'
        actual = HttpCredSSPAuth('', '', auth_mechanism=test_mechanism)
        assert len(actual.contexts) == 1
        assert actual.contexts[0].__name__ == 'NTLMContext'

    def test_tls1_2_option_default(self, monkeypatch):
        class SSLContextMock(object):
            def __init__(self, type):
                assert type == 6

            def set_cipher_list(self, cipher):
                assert cipher == b'ALL'

        monkeypatch.setattr('OpenSSL.SSL.Context', SSLContextMock)
        # The testing is actually happening in the mocking functions
        HttpCredSSPAuth('', '')

    def test_tlsv1_2_enabled(self, monkeypatch):
        class SSLContextMock(object):
            def __init__(self, type):
                assert type == 6

            def set_cipher_list(self, cipher):
                assert cipher == b'ALL'

        monkeypatch.setattr('OpenSSL.SSL.Context', SSLContextMock)
        # The testing is actually happening in the mocking functions
        HttpCredSSPAuth('', '', disable_tlsv1_2=False)

    def test_tlsv1_2_disabled(self, monkeypatch):
        class SSLContextMock(object):
            def __init__(self, type):
                assert type == 4

            def set_cipher_list(self, cipher):
                assert cipher == b'ALL'

            def set_options(self, options):
                assert options == 0x00000800 | 0x00000200

        monkeypatch.setattr('OpenSSL.SSL.Context', SSLContextMock)
        # The testing is actually happening in the mocking functions
        HttpCredSSPAuth('', '', disable_tlsv1_2=True)

    def test_verify_public_key_good(self):
        class NTLMContextTest(object):
            def unwrap(self, data):
                return server_pub_key_token

        test_credssp_context = HttpCredSSPAuth('', '')
        test_context = NTLMContextTest()
        test_ts_request = TSRequest()
        test_ts_request.parse_data(public_key_ts_request)
        test_public_key = b'\x00' + server_pub_key_token[1:]

        test_credssp_context._verify_public_keys(test_context, test_public_key,
                                                 test_ts_request)

    def test_verify_public_key_invalid(self):
        class NTLMContextTest(object):
            def unwrap(self, data):
                return server_pub_key_token

        test_credssp_context = HttpCredSSPAuth('', '')
        test_context = NTLMContextTest()
        test_ts_request = TSRequest()
        test_ts_request.parse_data(public_key_ts_request)

        # Use the wrong first byte to ensure the keys don't match
        test_public_key = b'\x01' + server_pub_key_token[1:]

        with pytest.raises(AuthenticationException) as exc:
            test_credssp_context._verify_public_keys(test_context,
                                                     test_public_key,
                                                     test_ts_request)

        assert str(exc.value) == "Could not verify key sent from the server," \
                                 " potential man in the middle attack"

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

        with pytest.raises(AuthenticationException) as exc:
            HttpCredSSPAuth._check_credssp_supported(test_request)

        assert str(exc.value) == "The server did not respond with a CredSSP " \
                                 "as an available auth method"

    def test_get_credssp_token_success(self):
        test_request = requests.Request('GET', '')
        test_request.headers['www-authenticate'] = 'CredSSP dGVzdA=='

        expected = 'test'.encode()

        actual = HttpCredSSPAuth._get_credssp_token(test_request)

        assert actual == expected

    def test_get_credssp_token_fail_no_token(self):
        test_request = requests.Request('GET', '')
        test_request.headers['www-authenticate'] = 'CredSSP'

        with pytest.raises(AuthenticationException) as exc:
            HttpCredSSPAuth._get_credssp_token(test_request)

        assert str(exc.value) == \
            "The server did not response with a CredSSP token, auth rejected"

    def test_get_credssp_token_fail_different_auth(self):
        test_request = requests.Request('GET', '')
        test_request.headers['www-authenticate'] = 'NTLM dGVzdA=='

        with pytest.raises(AuthenticationException) as exc:
            HttpCredSSPAuth._get_credssp_token(test_request)

        assert str(exc.value) == \
            'The server did not response with a CredSSP token, auth rejected'

    def test_set_credssp_token(self):
        test_request = requests.Request('GET', '')

        HttpCredSSPAuth._set_credssp_token(test_request, 'test'.encode())

        assert test_request.headers['Authorization'] == \
            'CredSSP dGVzdA=='.encode()


class TestHttpCredSSPAuthFunctional(object):

    @pytest.fixture(scope='class', autouse=True)
    def runner(self):
        server = os.environ.get('CREDSSP_SERVER', None)
        username = os.environ.get('CREDSSP_USERNAME', None)
        password = os.environ.get('CREDSSP_PASSWORD', None)

        if username and password and server:
            return server, username, password
        else:
            pytest.skip("CREDSSP_USERNAME, CREDSSP_PASSWORD, CREDSSP_SERVER "
                        "environment variables were not set, integration tests"
                        " will be skipped")

    def test_credssp_with_success_http(self, runner):
        test_url = "http://%s:5985/wsman" % runner[0]
        actual = self._send_request(test_url, runner[1], runner[2])

        # try and parse the xml response, will fail if the decryption failed
        ET.fromstring(actual)

    def test_credssp_with_success_https(self, runner):
        test_url = "https://%s:5986/wsman" % runner[0]
        actual = self._send_request(test_url, runner[1], runner[2])

        # try and parse the xml response, will fail if the decryption failed
        ET.fromstring(actual)

    def test_credssp_with_wrong_credentials(self, runner):
        # Wrong password, expect NTStatusException
        test_url = "https://%s:5986/wsman" % runner[0]

        with pytest.raises(AuthenticationException) as exc:
            self._send_request(test_url, runner[1], "fakepass")
        assert "NTLMContext: STATUS_LOGON_FAILURE" in str(exc.value)

    def _send_request(self, url, username, password):
        """
        Sends a request to the url with the credentials specified. Will also try
        send an encrypted config request and return the decrypted response
        """
        from urllib3.exceptions import InsecureRequestWarning
        warnings.simplefilter('ignore', category=InsecureRequestWarning)

        session = requests.Session()
        session.verify = False
        session.auth = HttpCredSSPAuth(username, password)
        request = requests.Request('POST', url, data='')
        request.headers['Content-Type'] = 'application/soap+xml;charset=UTF-8'
        request.headers['User-Agent'] = 'Python WinRM client'

        prepared_request = session.prepare_request(request)
        response = session.send(prepared_request)

        assert response.status_code == 200, \
            "Failed to authenticate with CredSSP to %s" % url

        response.raise_for_status()

        config_message = """
                <s:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:i="http://schemas.microsoft.com/wbem/wsman/1/cim/interactive.xsd" xmlns:wsmanfault="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identify/1/wsmanidentity.xsd" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:plugin="http://schemas.microsoft.com/wbem/wsman/1/config/PluginConfiguration" xmlns:cim="http://schemas.dmtf.org/wbem/wscim/1/common" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:wsdl="http://schemas.xmlsoap.org/wsdl" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wse="http://schemas.xmlsoap.org/ws/2004/08/eventing" xmlns:cert="http://schemas.microsoft.com/wbem/wsman/1/config/service/certmapping" xmlns:cfg="http://schemas.microsoft.com/wbem/wsman/1/config" xmlns:m="http://schemas.microsoft.com/wbem/wsman/1/machineid" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:sub="http://schemas.microsoft.com/wbem/wsman/1/subscription" xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing">
                <s:Header>
                    <p:SessionId s:mustUnderstand="false">uuid:11111111-1111-1111-1111-111111111111</p:SessionId>
                    <a:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action>
                    <a:To>%s</a:To>
                    <a:MessageID>uuid:11111111-1111-1111-1111-111111111111</a:MessageID>
                    <a:ReplyTo>
                        <a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
                    </a:ReplyTo>
                    <w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/config</w:ResourceURI>
                    <w:Locale xml:lang="en-US" s:mustUnderstand="false"/>
                    <w:MaxEnvelopeSize>153600</w:MaxEnvelopeSize>
                    <w:OperationTimeout>PT20S</w:OperationTimeout>
                    <p:DataLocale xml:lang="en-US" s:mustUnderstand="false"/>
                </s:Header>
                <s:Body/>
            </s:Envelope>""" % (url)
        encrypted_message = session.auth.wrap(config_message.encode('utf-8'))
        trailer_length = self._get_trailer_length(len(config_message), session.auth.cipher_negotiated)

        message_payload = \
            b"--Encrypted Boundary\r\n" \
            b"\tContent-Type: application/HTTP-CredSSP-session-encrypted\r\n" \
            b"\tOriginalContent: " \
            b"type=application/soap+xml;charset=UTF-8;Length=" + \
            str(len(config_message)).encode() + \
            b"\r\n" \
            b"--Encrypted Boundary\r\n" \
            b"\tContent-Type: application/octet-stream\r\n" + \
            struct.pack("<i", trailer_length) + encrypted_message + \
            b"--Encrypted Boundary--\r\n"

        request = requests.Request('POST', url, data=message_payload)
        prepared_request = session.prepare_request(request)
        prepared_request.headers['Content-Length'] = \
            str(len(prepared_request.body))
        prepared_request.headers['Content-Type'] = \
            'multipart/encrypted;' \
            'protocol="application/HTTP-CredSSP-session-encrypted";' \
            'boundary="Encrypted Boundary"'
        response = session.send(prepared_request)

        assert response.status_code == 200, \
            "Failed to send valid encrypted message to %s" % url

        encrypted_response = response.content.split(b'--Encrypted Boundary')[2]
        encrypted_payload = \
            encrypted_response.split(b'application/octet-stream\r\n')[1]
        decrypted_response = session.auth.unwrap(encrypted_payload[4:])

        return decrypted_response

    def _get_trailer_length(self, message_length, cipher_suite):
        # I really don't like the way this works but can't find a better way, MS
        # allows you to get this info through the struct SecPkgContext_StreamSizes
        # but there is no GSSAPI/OpenSSL equivalent so we need to calculate it
        # ourselves

        if re.match('^.*-GCM-[\w\d]*$', cipher_suite):
            # We are using GCM for the cipher suite, GCM has a fixed length of 16
            # bytes for the TLS trailer making it easy for us
            trailer_length = 16
        else:
            # We are not using GCM so need to calculate the trailer size. The
            # trailer length is equal to the length of the hmac + the length of the
            # padding required by the block cipher
            hash_algorithm = cipher_suite.split('-')[-1]

            # while there are other algorithms, SChannel doesn't support them
            # as of yet https://msdn.microsoft.com/en-us/library/windows/desktop/aa374757(v=vs.85).aspx
            if hash_algorithm == 'MD5':
                hash_length = 16
            elif hash_algorithm == 'SHA':
                hash_length = 20
            elif hash_algorithm == 'SHA256':
                hash_length = 32
            elif hash_algorithm == 'SHA384':
                hash_length = 48
            else:
                hash_length = 0

            pre_pad_length = message_length + hash_length

            if "RC4" in cipher_suite:
                # RC4 is a stream cipher so no padding would be added
                padding_length = 0
            elif "3DES" in cipher_suite:
                # 3DES is a 64 bit block cipher
                padding_length = 8 - (pre_pad_length % 8)
            else:
                # AES is a 128 bit block cipher
                padding_length = 16 - (pre_pad_length % 16)

            trailer_length = (pre_pad_length + padding_length) - message_length

        return trailer_length


class TestNTLMContext(object):

    def test_parse_username_with_backslash(self):
        test_username = 'DOMAIN\\USER'
        expected_domain = 'DOMAIN'
        expected_user = 'USER'

        actual = NTLMContext("", test_username, "")
        assert actual.domain == expected_domain
        assert actual.username == expected_user

    def test_parse_username_with_upn(self):
        test_username = 'USER@DOMAIN.LOCAL'
        expected_domain = ''
        expected_user = test_username

        actual = NTLMContext("", test_username, "")
        assert actual.domain == expected_domain
        assert actual.username == expected_user

    def test_parse_username_without_domain(self):
        test_username = 'USER'
        expected_domain = ''
        expected_user = 'USER'

        actual = NTLMContext("", test_username, "")
        assert actual.domain == expected_domain
        assert actual.username == expected_user
