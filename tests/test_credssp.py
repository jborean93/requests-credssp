import os
import re
import requests
import struct
import warnings

import pytest

from xml.etree import ElementTree as ET

from requests_credssp.credssp import CredSSPContext, HttpCredSSPAuth
from requests_credssp.exceptions import AuthenticationException, InvalidConfigurationException, NTStatusException



class TestHttpCredSSPAuth(object):

    def test_invalid_auth_mechanism(self):
        expected = "Invalid auth_mechanism supplied fake, must be auto, ntlm, or kerberos"
        with pytest.raises(InvalidConfigurationException, match=expected):
            CredSSPContext("", "", "", auth_mechanism="fake")

    def test_check_credssp_supported(self):
        response = requests.Response()
        response.headers['www-authenticate'] = "CredSSP"
        HttpCredSSPAuth._check_credssp_supported(response)

    def test_check_credssp_supported_multiple(self):
        response = requests.Response()
        response.headers['www-authenticate'] = "Negotiate, Credssp, " \
                                               "Realm='WSMan'"
        HttpCredSSPAuth._check_credssp_supported(response)

    def test_check_credssp_supported_fail(self):
        response = requests.Response()
        response.headers['www-authenticate'] = "Negotiate"
        with pytest.raises(AuthenticationException) as exc:
            HttpCredSSPAuth._check_credssp_supported(response)
        assert str(exc.value) == "The server did not response CredSSP being " \
                                 "an available authentication method - " \
                                 "actual: 'Negotiate'"

    def test_set_credssp_token(self):
        request = requests.Request('GET', '')
        expected = b"CredSSP YWJj"
        HttpCredSSPAuth._set_credssp_token(request, b"abc")
        actual = request.headers['Authorization']
        assert actual == expected

    def test_get_credssp_token(self):
        pattern = re.compile(r"CredSSP ([^,\s]*)$", re.I)
        response = requests.Response()
        response.headers['www-authenticate'] = "CredSSP YWJj"
        expected = b"abc"
        actual = HttpCredSSPAuth._get_credssp_token(response, pattern,
                                                    "step 1")
        assert actual == expected

    def test_get_credssp_token_fail_no_header(self):
        pattern = re.compile(r"CredSSP ([^,\s]*)$", re.I)
        response = requests.Response()
        with pytest.raises(AuthenticationException) as exc:
            HttpCredSSPAuth._get_credssp_token(response, pattern, "step 1")
        assert str(exc.value) == "Server did not response with a CredSSP " \
                                 "token after step step 1 - actual ''"

    def test_get_credssp_token_fail_no_credssp_token(self):
        pattern = re.compile(r"CredSSP ([^,\s]*)$", re.I)
        response = requests.Response()
        response.headers['www-authenticate'] = "NTLM YWJj"
        with pytest.raises(AuthenticationException) as exc:
            HttpCredSSPAuth._get_credssp_token(response, pattern, "step 1")
        assert str(exc.value) == "Server did not response with a CredSSP " \
                                 "token after step step 1 - actual 'NTLM YWJj'"


class TestHttpCredSSPAuthFunctional(object):

    @pytest.fixture(scope='class', autouse=True)
    def runner(self):
        server = os.environ.get('CREDSSP_SERVER', "server2019.domain.test")
        username = os.environ.get('CREDSSP_USERNAME', "vagrant-domain@DOMAIN.TEST")
        password = os.environ.get('CREDSSP_PASSWORD', "VagrantPass1")

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

        with pytest.raises(NTStatusException) as exc:
            self._send_request(test_url, runner[1], "fakepass")
        assert str(exc.value) == "Received error status from the server: " \
                                 "(3221225581) STATUS_LOGON_FAILURE 0xc000006d"

    def test_credssp_minimum_client_fail(self, runner):
        test_url = "https://%s:5986/wsman" % runner[0]

        with pytest.raises(AuthenticationException, match="did not meet the minimum requirements of 100"):
            self._send_request(test_url, runner[1], runner[2],
                               minimum_version=100)

    def test_credssp_with_ntlm_explicit(self, runner):
        test_url = "https://%s:5986/wsman" % runner[0]
        actual = self._send_request(test_url, runner[1], runner[2],
                                    auth_mech="ntlm")

        # try and parse the xml response, will fail if the decryption failed
        ET.fromstring(actual)

    def _send_request(self, url, username, password, auth_mech="auto",
                      minimum_version=2):
        """
        Sends a request to the url with the credentials specified. Will also
        try send an encrypted config request and return the decrypted response
        """
        from urllib3.exceptions import InsecureRequestWarning
        warnings.simplefilter('ignore', category=InsecureRequestWarning)

        session = requests.Session()
        session.verify = False
        session.auth = HttpCredSSPAuth(username, password,
                                       auth_mechanism=auth_mech,
                                       minimum_version=minimum_version)
        request = requests.Request('POST', url, data='')
        request.headers['Content-Type'] = 'application/soap+xml;charset=UTF-8'
        request.headers['User-Agent'] = 'Python WinRM client'

        prepared_request = session.prepare_request(request)
        response = session.send(prepared_request)

        assert response.status_code == 200, \
            "Failed to authenticate with CredSSP to %s" % url
        response.raise_for_status()

        hostname = next(iter(session.auth.contexts))
        context = session.auth.contexts[hostname]

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

        assert context.tls_connection.get_cipher_name() == context.tls_connection.cipher()[0]
        header, encrypted_message, _ = context.wrap_winrm(config_message.encode('utf-8'))

        message_payload = \
            b"--Encrypted Boundary\r\n" \
            b"\tContent-Type: application/HTTP-CredSSP-session-encrypted\r\n" \
            b"\tOriginalContent: " \
            b"type=application/soap+xml;charset=UTF-8;Length=" + \
            str(len(config_message)).encode() + \
            b"\r\n" \
            b"--Encrypted Boundary\r\n" \
            b"\tContent-Type: application/octet-stream\r\n" + \
            struct.pack("<i", len(header)) + header + encrypted_message + \
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

        header_len = struct.unpack("<I", encrypted_payload[:4])[0]
        decrypted_response = context.unwrap_winrm(encrypted_payload[4:header_len + 4],
            encrypted_payload[4 + header_len:])

        return decrypted_response
