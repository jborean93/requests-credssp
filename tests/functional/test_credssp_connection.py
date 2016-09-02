import unittest2 as unittest
import requests_credssp
import requests

from requests_credssp.exceptions import NTStatusException

username = '.\\User'
password = 'Password01'
url = 'https://127.0.0.1:5986/wsman'

"""
This is a test with a real WinRM instance on a Windows server to test out the CredSSP authentication.

This will check for a response code of 200 which is an indication of a successful authentication.

Appveyor runs on Server 2012 R2 which supports TLS 1.2 by default and returns error codes in the TSRequest. The
failure test will assert that the error code was reached.
"""

class Test_Functional(unittest.TestCase):
    def test_credssp_with_success(self):
        actual = send_request(url, username, password)
        actual = actual.status_code

        assert actual == 200

    def test_credssp_with_wrong_credentials(self):
        # Wrong password, expect NTStatusException
        with self.assertRaises(NTStatusException) as context:
            send_request(url, username, 'fakepass')

        self.assertTrue("STATUS_LOGON_FAILURE - b'c000006d'", context.exception.args)

def send_request(url, username, password):
    """
    Sends a request to the url with the credentials specified. Returns the final response
    """
    session = requests.Session()
    session.verify = False
    session.auth = requests_credssp.HttpCredSSPAuth(username, password)
    request = requests.Request('POST', url)
    request.headers['Content-Type'] = 'application/soap+xml;charset=UTF-8'
    request.headers['User-Agent'] = 'Python WinRM client'

    prepared_request = session.prepare_request(request)

    return session.send(prepared_request)

