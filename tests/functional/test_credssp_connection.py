import unittest2 as unittest
import re
import requests_credssp
import requests
import struct

from requests_credssp.exceptions import NTStatusException
from xml.etree import ElementTree as ET

username = '.\\User'
password = 'Password01'
url = '{0}://127.0.0.1:{1}/wsman'

"""
This is a test with a real WinRM instance on a Windows server to test out the CredSSP authentication.

This will check for a response code of 200 which is an indication of a successful authentication.

Appveyor runs on Server 2012 R2 which supports TLS 1.2 by default and returns error codes in the TSRequest. The
failure test will assert that the error code was reached.
"""

class Test_Functional(unittest.TestCase):
    def test_credssp_with_success_http(self):
        test_url = url.format('http', 5985)
        actual = send_request(test_url, username, password)

        # try and parse the xml response, will fail if the decryption failed
        ET.fromstring(actual)


    def test_credssp_with_success_https(self):
        test_url = url.format('https', 5986)
        actual = send_request(test_url, username, password)

        # try and parse the xml response, will fail if the decryption failed
        ET.fromstring(actual)

    def test_credssp_with_wrong_credentials(self):
        # Wrong password, expect NTStatusException
        test_url = url.format('https', 5986)
        with self.assertRaises(NTStatusException) as context:
            send_request(test_url, username, 'fakepass')

        self.assertTrue("STATUS_LOGON_FAILURE - b'c000006d'", context.exception.args)

def send_request(url, username, password):
    """
    Sends a request to the url with the credentials specified. Will also try
    send an encrypted config request and return the decrypted response
    """
    session = requests.Session()
    session.verify = False
    session.auth = requests_credssp.HttpCredSSPAuth(username, password)
    request = requests.Request('POST', url, data='')
    request.headers['Content-Type'] = 'application/soap+xml;charset=UTF-8'
    request.headers['User-Agent'] = 'Python WinRM client'

    prepared_request = session.prepare_request(request)
    response = session.send(prepared_request)

    assert response.status_code == 200, "Failed to authenticate with CredSSP to %s" % url

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
    encrypted_message = session.auth.wrap(config_message)
    trailer_length = get_trailer_length(len(config_message), session.auth.cipher_negotiated)

    message_payload = b"--Encrypted Boundary\r\n" \
                      b"\tContent-Type: application/HTTP-CredSSP-session-encrypted\r\n" \
                      b"\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=" + \
                      str(len(config_message)).encode() + \
                      b"\r\n" \
                      b"--Encrypted Boundary\r\n" \
                      b"\tContent-Type: application/octet-stream\r\n" + \
                      struct.pack("<i", trailer_length) + encrypted_message + \
                      b"--Encrypted Boundary--\r\n"

    request = requests.Request('POST', url, data=message_payload)
    prepared_request = session.prepare_request(request)
    prepared_request.headers['Content-Length'] = str(len(prepared_request.body))
    prepared_request.headers['Content-Type'] = 'multipart/encrypted;' \
                                               'protocol="application/HTTP-CredSSP-session-encrypted";' \
                                               'boundary="Encrypted Boundary"'
    response = session.send(prepared_request)

    assert response.status_code == 200, "Failed to send valid encrypted message to %s" % url

    encrypted_response = response.content.split(b'--Encrypted Boundary')[2]
    encrypted_payload = encrypted_response.split(b'application/octet-stream\r\n')[1]
    decrypted_response = session.auth.unwrap(encrypted_payload[4:])

    return decrypted_response

def get_trailer_length(message_length, cipher_suite):
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
