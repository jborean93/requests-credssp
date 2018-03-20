import os
import re
import requests
import struct
import warnings

import pytest

from xml.etree import ElementTree as ET

from requests_credssp.asn_structures import SPNEGOMechs
from requests_credssp.credssp import CredSSPContext, GSSApiContext, \
    HttpCredSSPAuth, NTLMContext, SPNEGO
from requests_credssp.exceptions import AuthenticationException, \
    InvalidConfigurationException, NTStatusException


class TestCredSSPContext(object):

    def test_tls_default(self, monkeypatch):
        class SSLContextMock(object):
            def __init__(self, type):
                assert type == 6

            def set_cipher_list(self, cipher):
                assert cipher == b'ALL'

        monkeypatch.setattr('OpenSSL.SSL.Context', SSLContextMock)

        # The testing is actually happening in the mocked functions
        CredSSPContext("", "", "")

    def test_tls_enable_1_2(self, monkeypatch):
        class SSLContextMock(object):
            def __init__(self, type):
                assert type == 6

            def set_cipher_list(self, cipher):
                assert cipher == b'ALL'

        monkeypatch.setattr('OpenSSL.SSL.Context', SSLContextMock)

        # The testing is actually happening in the mocked functions
        CredSSPContext("", "", "", disable_tlsv1_2=False)

    def test_tls_disable_1_2(self, monkeypatch):
        class SSLContextMock(object):
            def __init__(self, type):
                assert type == 4

            def set_cipher_list(self, cipher):
                assert cipher == b'ALL'

            def set_options(self, options):
                assert options == 0x00000800 | 0x00000200

        monkeypatch.setattr('OpenSSL.SSL.Context', SSLContextMock)

        # The testing is actually happening in the mocked functions
        CredSSPContext("", "", "", disable_tlsv1_2=True)

    def test_build_pub_key_auth_old_no_auth(self):
        class FakeContext(object):
            def wrap(self, data):
                # just pads an extra 4 null chars to verify wrap was called
                return data + (b"\x00" * 4)

        context = FakeContext()
        credssp = CredSSPContext("", "", "")
        nonce = None
        auth_token = None
        public_key = b"\x30\x82\x01\x0a\x02\x82\x01\x01" \
                     b"\x00\x9d\xb9\xd2\xd9\x76\x57\x8b" \
                     b"\x22\x3a\x25\xc5\x4d\xd0\xef\xa9" \
                     b"\x29\x1e\x7b\x4e\xec\x5e\x13\x00" \
                     b"\x06\x4e\xba\xad\xf3\x0b\x84\xd9" \
                     b"\x37\xaf\x2f\x2c\x65\x9e\x9b\xaf" \
                     b"\x47\xf9\x63\x63\x63\x9f\x7f\x9c" \
                     b"\xdd\x3e\x85\x96\xb3\x46\x33\x42" \
                     b"\x0a\x0c\x6d\xee\x67\x78\xa9\xf0" \
                     b"\x73\xdc\x02\x82\x30\x61\x49\x29" \
                     b"\xf7\x55\xb3\x43\x68\x40\xfc\xa1" \
                     b"\x72\xd9\xca\xf3\x1a\xa4\x99\x9d" \
                     b"\x52\xc3\x98\x1a\x8a\x27\xf8\x8b" \
                     b"\xb8\xe3\xdc\x1a\x82\x2b\x92\x1e" \
                     b"\xbc\x50\x8c\xa3\x6a\x1c\x25\x2f" \
                     b"\x39\xb5\x90\xc5\x56\x19\x01\x03" \
                     b"\x19\xfb\x01\xc9\x16\x7a\x66\x7c" \
                     b"\x78\x64\x7b\xd4\xe6\x40\x65\xdb" \
                     b"\x09\x21\x8e\x8b\xa5\x99\xac\xb3" \
                     b"\x92\xf2\x46\xf3\xa2\x88\x0b\x48" \
                     b"\x83\x3f\xbf\x74\xaf\x03\xd4\xf7" \
                     b"\x50\x52\x3f\xea\xde\xf1\x33\x04" \
                     b"\xc2\xb4\x3b\x8e\x54\xa2\x57\x26" \
                     b"\x5a\x66\x28\x64\xfb\xfd\x09\x21" \
                     b"\xbe\xbd\x93\x97\xc2\x70\x80\x69" \
                     b"\x99\x36\x37\x71\x0f\x92\x32\x18" \
                     b"\xe7\x73\x8a\x73\xc6\xdf\xb1\xb7" \
                     b"\xfb\xf2\xaf\xa3\x84\xaf\x69\x12" \
                     b"\xe0\xf0\x87\xc7\xb4\x32\x3f\x56" \
                     b"\xfc\xba\x10\x88\x62\xfb\xa1\x69" \
                     b"\x30\x22\x89\x04\xdd\x51\xa9\x8e" \
                     b"\x3e\x7a\x32\x79\x17\x1c\x4f\x47" \
                     b"\x2b\xf1\xf9\xf4\x1e\x35\x09\xfa" \
                     b"\x93\x02\x03\x01\x00\x01"

        expected = b"\x30\x82\x01\x1F" \
                   b"\xa0\x03" \
                   b"\x02\x01" \
                   b"\x06" \
                   b"\xa3\x82\x01\x16" \
                   b"\x04\x82\x01\x12" \
                   b"\x30\x82\x01\x0a\x02\x82\x01\x01" \
                   b"\x00\x9d\xb9\xd2\xd9\x76\x57\x8b" \
                   b"\x22\x3a\x25\xc5\x4d\xd0\xef\xa9" \
                   b"\x29\x1e\x7b\x4e\xec\x5e\x13\x00" \
                   b"\x06\x4e\xba\xad\xf3\x0b\x84\xd9" \
                   b"\x37\xaf\x2f\x2c\x65\x9e\x9b\xaf" \
                   b"\x47\xf9\x63\x63\x63\x9f\x7f\x9c" \
                   b"\xdd\x3e\x85\x96\xb3\x46\x33\x42" \
                   b"\x0a\x0c\x6d\xee\x67\x78\xa9\xf0" \
                   b"\x73\xdc\x02\x82\x30\x61\x49\x29" \
                   b"\xf7\x55\xb3\x43\x68\x40\xfc\xa1" \
                   b"\x72\xd9\xca\xf3\x1a\xa4\x99\x9d" \
                   b"\x52\xc3\x98\x1a\x8a\x27\xf8\x8b" \
                   b"\xb8\xe3\xdc\x1a\x82\x2b\x92\x1e" \
                   b"\xbc\x50\x8c\xa3\x6a\x1c\x25\x2f" \
                   b"\x39\xb5\x90\xc5\x56\x19\x01\x03" \
                   b"\x19\xfb\x01\xc9\x16\x7a\x66\x7c" \
                   b"\x78\x64\x7b\xd4\xe6\x40\x65\xdb" \
                   b"\x09\x21\x8e\x8b\xa5\x99\xac\xb3" \
                   b"\x92\xf2\x46\xf3\xa2\x88\x0b\x48" \
                   b"\x83\x3f\xbf\x74\xaf\x03\xd4\xf7" \
                   b"\x50\x52\x3f\xea\xde\xf1\x33\x04" \
                   b"\xc2\xb4\x3b\x8e\x54\xa2\x57\x26" \
                   b"\x5a\x66\x28\x64\xfb\xfd\x09\x21" \
                   b"\xbe\xbd\x93\x97\xc2\x70\x80\x69" \
                   b"\x99\x36\x37\x71\x0f\x92\x32\x18" \
                   b"\xe7\x73\x8a\x73\xc6\xdf\xb1\xb7" \
                   b"\xfb\xf2\xaf\xa3\x84\xaf\x69\x12" \
                   b"\xe0\xf0\x87\xc7\xb4\x32\x3f\x56" \
                   b"\xfc\xba\x10\x88\x62\xfb\xa1\x69" \
                   b"\x30\x22\x89\x04\xdd\x51\xa9\x8e" \
                   b"\x3e\x7a\x32\x79\x17\x1c\x4f\x47" \
                   b"\x2b\xf1\xf9\xf4\x1e\x35\x09\xfa" \
                   b"\x93\x02\x03\x01\x00\x01" \
                   b"\x00\x00\x00\x00"
        actual = credssp._build_pub_key_auth(context, nonce, auth_token,
                                             public_key)
        assert actual == expected

    def test_build_pub_key_auth_old_with_auth(self):
        class FakeContext(object):
            def wrap(self, data):
                # just pads an extra 4 null chars to verify wrap was called
                return data + (b"\x00" * 4)

        context = FakeContext()
        credssp = CredSSPContext("", "", "")
        nonce = None
        auth_token = b"\x01\x02\x03\x04"
        public_key = b"\x30\x82\x01\x0a\x02\x82\x01\x01" \
                     b"\x00\x9d\xb9\xd2\xd9\x76\x57\x8b" \
                     b"\x22\x3a\x25\xc5\x4d\xd0\xef\xa9" \
                     b"\x29\x1e\x7b\x4e\xec\x5e\x13\x00" \
                     b"\x06\x4e\xba\xad\xf3\x0b\x84\xd9" \
                     b"\x37\xaf\x2f\x2c\x65\x9e\x9b\xaf" \
                     b"\x47\xf9\x63\x63\x63\x9f\x7f\x9c" \
                     b"\xdd\x3e\x85\x96\xb3\x46\x33\x42" \
                     b"\x0a\x0c\x6d\xee\x67\x78\xa9\xf0" \
                     b"\x73\xdc\x02\x82\x30\x61\x49\x29" \
                     b"\xf7\x55\xb3\x43\x68\x40\xfc\xa1" \
                     b"\x72\xd9\xca\xf3\x1a\xa4\x99\x9d" \
                     b"\x52\xc3\x98\x1a\x8a\x27\xf8\x8b" \
                     b"\xb8\xe3\xdc\x1a\x82\x2b\x92\x1e" \
                     b"\xbc\x50\x8c\xa3\x6a\x1c\x25\x2f" \
                     b"\x39\xb5\x90\xc5\x56\x19\x01\x03" \
                     b"\x19\xfb\x01\xc9\x16\x7a\x66\x7c" \
                     b"\x78\x64\x7b\xd4\xe6\x40\x65\xdb" \
                     b"\x09\x21\x8e\x8b\xa5\x99\xac\xb3" \
                     b"\x92\xf2\x46\xf3\xa2\x88\x0b\x48" \
                     b"\x83\x3f\xbf\x74\xaf\x03\xd4\xf7" \
                     b"\x50\x52\x3f\xea\xde\xf1\x33\x04" \
                     b"\xc2\xb4\x3b\x8e\x54\xa2\x57\x26" \
                     b"\x5a\x66\x28\x64\xfb\xfd\x09\x21" \
                     b"\xbe\xbd\x93\x97\xc2\x70\x80\x69" \
                     b"\x99\x36\x37\x71\x0f\x92\x32\x18" \
                     b"\xe7\x73\x8a\x73\xc6\xdf\xb1\xb7" \
                     b"\xfb\xf2\xaf\xa3\x84\xaf\x69\x12" \
                     b"\xe0\xf0\x87\xc7\xb4\x32\x3f\x56" \
                     b"\xfc\xba\x10\x88\x62\xfb\xa1\x69" \
                     b"\x30\x22\x89\x04\xdd\x51\xa9\x8e" \
                     b"\x3e\x7a\x32\x79\x17\x1c\x4f\x47" \
                     b"\x2b\xf1\xf9\xf4\x1e\x35\x09\xfa" \
                     b"\x93\x02\x03\x01\x00\x01"

        expected = b"\x30\x82\x01\x2D" \
                   b"\xa0\x03" \
                   b"\x02\x01" \
                   b"\x06" \
                   b"\xa1\x0C" \
                   b"\x30\x0A" \
                   b"\x30\x08" \
                   b"\xa0\x06" \
                   b"\x04\x04" \
                   b"\x01\x02\x03\x04" \
                   b"\xa3\x82\x01\x16" \
                   b"\x04\x82\x01\x12" \
                   b"\x30\x82\x01\x0a\x02\x82\x01\x01" \
                   b"\x00\x9d\xb9\xd2\xd9\x76\x57\x8b" \
                   b"\x22\x3a\x25\xc5\x4d\xd0\xef\xa9" \
                   b"\x29\x1e\x7b\x4e\xec\x5e\x13\x00" \
                   b"\x06\x4e\xba\xad\xf3\x0b\x84\xd9" \
                   b"\x37\xaf\x2f\x2c\x65\x9e\x9b\xaf" \
                   b"\x47\xf9\x63\x63\x63\x9f\x7f\x9c" \
                   b"\xdd\x3e\x85\x96\xb3\x46\x33\x42" \
                   b"\x0a\x0c\x6d\xee\x67\x78\xa9\xf0" \
                   b"\x73\xdc\x02\x82\x30\x61\x49\x29" \
                   b"\xf7\x55\xb3\x43\x68\x40\xfc\xa1" \
                   b"\x72\xd9\xca\xf3\x1a\xa4\x99\x9d" \
                   b"\x52\xc3\x98\x1a\x8a\x27\xf8\x8b" \
                   b"\xb8\xe3\xdc\x1a\x82\x2b\x92\x1e" \
                   b"\xbc\x50\x8c\xa3\x6a\x1c\x25\x2f" \
                   b"\x39\xb5\x90\xc5\x56\x19\x01\x03" \
                   b"\x19\xfb\x01\xc9\x16\x7a\x66\x7c" \
                   b"\x78\x64\x7b\xd4\xe6\x40\x65\xdb" \
                   b"\x09\x21\x8e\x8b\xa5\x99\xac\xb3" \
                   b"\x92\xf2\x46\xf3\xa2\x88\x0b\x48" \
                   b"\x83\x3f\xbf\x74\xaf\x03\xd4\xf7" \
                   b"\x50\x52\x3f\xea\xde\xf1\x33\x04" \
                   b"\xc2\xb4\x3b\x8e\x54\xa2\x57\x26" \
                   b"\x5a\x66\x28\x64\xfb\xfd\x09\x21" \
                   b"\xbe\xbd\x93\x97\xc2\x70\x80\x69" \
                   b"\x99\x36\x37\x71\x0f\x92\x32\x18" \
                   b"\xe7\x73\x8a\x73\xc6\xdf\xb1\xb7" \
                   b"\xfb\xf2\xaf\xa3\x84\xaf\x69\x12" \
                   b"\xe0\xf0\x87\xc7\xb4\x32\x3f\x56" \
                   b"\xfc\xba\x10\x88\x62\xfb\xa1\x69" \
                   b"\x30\x22\x89\x04\xdd\x51\xa9\x8e" \
                   b"\x3e\x7a\x32\x79\x17\x1c\x4f\x47" \
                   b"\x2b\xf1\xf9\xf4\x1e\x35\x09\xfa" \
                   b"\x93\x02\x03\x01\x00\x01" \
                   b"\x00\x00\x00\x00"
        actual = credssp._build_pub_key_auth(context, nonce, auth_token,
                                             public_key)
        assert actual == expected

    def test_build_pub_key_auth_new_no_auth(self):
        class FakeContext(object):
            def wrap(self, data):
                # just pads an extra 4 null chars to verify wrap was called
                return data + (b"\x00" * 4)

        context = FakeContext()
        credssp = CredSSPContext("", "", "")
        nonce = b"\xff" * 32
        auth_token = None
        public_key = b"\x30\x82\x01\x0a\x02\x82\x01\x01" \
                     b"\x00\x9d\xb9\xd2\xd9\x76\x57\x8b" \
                     b"\x22\x3a\x25\xc5\x4d\xd0\xef\xa9" \
                     b"\x29\x1e\x7b\x4e\xec\x5e\x13\x00" \
                     b"\x06\x4e\xba\xad\xf3\x0b\x84\xd9" \
                     b"\x37\xaf\x2f\x2c\x65\x9e\x9b\xaf" \
                     b"\x47\xf9\x63\x63\x63\x9f\x7f\x9c" \
                     b"\xdd\x3e\x85\x96\xb3\x46\x33\x42" \
                     b"\x0a\x0c\x6d\xee\x67\x78\xa9\xf0" \
                     b"\x73\xdc\x02\x82\x30\x61\x49\x29" \
                     b"\xf7\x55\xb3\x43\x68\x40\xfc\xa1" \
                     b"\x72\xd9\xca\xf3\x1a\xa4\x99\x9d" \
                     b"\x52\xc3\x98\x1a\x8a\x27\xf8\x8b" \
                     b"\xb8\xe3\xdc\x1a\x82\x2b\x92\x1e" \
                     b"\xbc\x50\x8c\xa3\x6a\x1c\x25\x2f" \
                     b"\x39\xb5\x90\xc5\x56\x19\x01\x03" \
                     b"\x19\xfb\x01\xc9\x16\x7a\x66\x7c" \
                     b"\x78\x64\x7b\xd4\xe6\x40\x65\xdb" \
                     b"\x09\x21\x8e\x8b\xa5\x99\xac\xb3" \
                     b"\x92\xf2\x46\xf3\xa2\x88\x0b\x48" \
                     b"\x83\x3f\xbf\x74\xaf\x03\xd4\xf7" \
                     b"\x50\x52\x3f\xea\xde\xf1\x33\x04" \
                     b"\xc2\xb4\x3b\x8e\x54\xa2\x57\x26" \
                     b"\x5a\x66\x28\x64\xfb\xfd\x09\x21" \
                     b"\xbe\xbd\x93\x97\xc2\x70\x80\x69" \
                     b"\x99\x36\x37\x71\x0f\x92\x32\x18" \
                     b"\xe7\x73\x8a\x73\xc6\xdf\xb1\xb7" \
                     b"\xfb\xf2\xaf\xa3\x84\xaf\x69\x12" \
                     b"\xe0\xf0\x87\xc7\xb4\x32\x3f\x56" \
                     b"\xfc\xba\x10\x88\x62\xfb\xa1\x69" \
                     b"\x30\x22\x89\x04\xdd\x51\xa9\x8e" \
                     b"\x3e\x7a\x32\x79\x17\x1c\x4f\x47" \
                     b"\x2b\xf1\xf9\xf4\x1e\x35\x09\xfa" \
                     b"\x93\x02\x03\x01\x00\x01"

        expected = b"\x30\x51" \
                   b"\xa0\x03" \
                   b"\x02\x01" \
                   b"\x06" \
                   b"\xa3\x26" \
                   b"\x04\x24" \
                   b"\xe6\x43\x6d\x98\xee\x73\x5a\x5f" \
                   b"\xba\xe3\x0b\xd7\xd8\x9b\xeb\xb3" \
                   b"\xec\x28\xf7\xe3\xf9\x6c\x95\xf4" \
                   b"\x62\xb2\xf5\xe9\x02\xe1\xb6\x38" \
                   b"\x00\x00\x00\x00" \
                   b"\xa5\x22" \
                   b"\x04\x20" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff"
        actual = credssp._build_pub_key_auth(context, nonce, auth_token,
                                             public_key)
        assert actual == expected

    def test_build_pub_key_auth_new_with_auth(self):
        class FakeContext(object):
            def wrap(self, data):
                # just pads an extra 4 null chars to verify wrap was called
                return data + (b"\x00" * 4)

        context = FakeContext()
        credssp = CredSSPContext("", "", "")
        nonce = b"\xff" * 32
        auth_token = b"\x01\x02\x03\x04"
        public_key = b"\x30\x82\x01\x0a\x02\x82\x01\x01" \
                     b"\x00\x9d\xb9\xd2\xd9\x76\x57\x8b" \
                     b"\x22\x3a\x25\xc5\x4d\xd0\xef\xa9" \
                     b"\x29\x1e\x7b\x4e\xec\x5e\x13\x00" \
                     b"\x06\x4e\xba\xad\xf3\x0b\x84\xd9" \
                     b"\x37\xaf\x2f\x2c\x65\x9e\x9b\xaf" \
                     b"\x47\xf9\x63\x63\x63\x9f\x7f\x9c" \
                     b"\xdd\x3e\x85\x96\xb3\x46\x33\x42" \
                     b"\x0a\x0c\x6d\xee\x67\x78\xa9\xf0" \
                     b"\x73\xdc\x02\x82\x30\x61\x49\x29" \
                     b"\xf7\x55\xb3\x43\x68\x40\xfc\xa1" \
                     b"\x72\xd9\xca\xf3\x1a\xa4\x99\x9d" \
                     b"\x52\xc3\x98\x1a\x8a\x27\xf8\x8b" \
                     b"\xb8\xe3\xdc\x1a\x82\x2b\x92\x1e" \
                     b"\xbc\x50\x8c\xa3\x6a\x1c\x25\x2f" \
                     b"\x39\xb5\x90\xc5\x56\x19\x01\x03" \
                     b"\x19\xfb\x01\xc9\x16\x7a\x66\x7c" \
                     b"\x78\x64\x7b\xd4\xe6\x40\x65\xdb" \
                     b"\x09\x21\x8e\x8b\xa5\x99\xac\xb3" \
                     b"\x92\xf2\x46\xf3\xa2\x88\x0b\x48" \
                     b"\x83\x3f\xbf\x74\xaf\x03\xd4\xf7" \
                     b"\x50\x52\x3f\xea\xde\xf1\x33\x04" \
                     b"\xc2\xb4\x3b\x8e\x54\xa2\x57\x26" \
                     b"\x5a\x66\x28\x64\xfb\xfd\x09\x21" \
                     b"\xbe\xbd\x93\x97\xc2\x70\x80\x69" \
                     b"\x99\x36\x37\x71\x0f\x92\x32\x18" \
                     b"\xe7\x73\x8a\x73\xc6\xdf\xb1\xb7" \
                     b"\xfb\xf2\xaf\xa3\x84\xaf\x69\x12" \
                     b"\xe0\xf0\x87\xc7\xb4\x32\x3f\x56" \
                     b"\xfc\xba\x10\x88\x62\xfb\xa1\x69" \
                     b"\x30\x22\x89\x04\xdd\x51\xa9\x8e" \
                     b"\x3e\x7a\x32\x79\x17\x1c\x4f\x47" \
                     b"\x2b\xf1\xf9\xf4\x1e\x35\x09\xfa" \
                     b"\x93\x02\x03\x01\x00\x01"

        expected = b"\x30\x5F" \
                   b"\xa0\x03" \
                   b"\x02\x01" \
                   b"\x06" \
                   b"\xa1\x0c" \
                   b"\x30\x0a" \
                   b"\x30\x08" \
                   b"\xa0\x06" \
                   b"\x04\x04" \
                   b"\x01\x02\x03\x04" \
                   b"\xa3\x26" \
                   b"\x04\x24" \
                   b"\xe6\x43\x6d\x98\xee\x73\x5a\x5f" \
                   b"\xba\xe3\x0b\xd7\xd8\x9b\xeb\xb3" \
                   b"\xec\x28\xf7\xe3\xf9\x6c\x95\xf4" \
                   b"\x62\xb2\xf5\xe9\x02\xe1\xb6\x38" \
                   b"\x00\x00\x00\x00" \
                   b"\xa5\x22" \
                   b"\x04\x20" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff"
        actual = credssp._build_pub_key_auth(context, nonce, auth_token,
                                             public_key)
        assert actual == expected

    def test_verify_pub_key_old(self):
        credssp = CredSSPContext("", "", "")
        nonce = None
        response_key = b"\x31\x82\x01\x0a\x02\x82\x01\x01" \
                       b"\x00\x9d\xb9\xd2\xd9\x76\x57\x8b" \
                       b"\x22\x3a\x25\xc5\x4d\xd0\xef\xa9" \
                       b"\x29\x1e\x7b\x4e\xec\x5e\x13\x00" \
                       b"\x06\x4e\xba\xad\xf3\x0b\x84\xd9" \
                       b"\x37\xaf\x2f\x2c\x65\x9e\x9b\xaf" \
                       b"\x47\xf9\x63\x63\x63\x9f\x7f\x9c" \
                       b"\xdd\x3e\x85\x96\xb3\x46\x33\x42" \
                       b"\x0a\x0c\x6d\xee\x67\x78\xa9\xf0" \
                       b"\x73\xdc\x02\x82\x30\x61\x49\x29" \
                       b"\xf7\x55\xb3\x43\x68\x40\xfc\xa1" \
                       b"\x72\xd9\xca\xf3\x1a\xa4\x99\x9d" \
                       b"\x52\xc3\x98\x1a\x8a\x27\xf8\x8b" \
                       b"\xb8\xe3\xdc\x1a\x82\x2b\x92\x1e" \
                       b"\xbc\x50\x8c\xa3\x6a\x1c\x25\x2f" \
                       b"\x39\xb5\x90\xc5\x56\x19\x01\x03" \
                       b"\x19\xfb\x01\xc9\x16\x7a\x66\x7c" \
                       b"\x78\x64\x7b\xd4\xe6\x40\x65\xdb" \
                       b"\x09\x21\x8e\x8b\xa5\x99\xac\xb3" \
                       b"\x92\xf2\x46\xf3\xa2\x88\x0b\x48" \
                       b"\x83\x3f\xbf\x74\xaf\x03\xd4\xf7" \
                       b"\x50\x52\x3f\xea\xde\xf1\x33\x04" \
                       b"\xc2\xb4\x3b\x8e\x54\xa2\x57\x26" \
                       b"\x5a\x66\x28\x64\xfb\xfd\x09\x21" \
                       b"\xbe\xbd\x93\x97\xc2\x70\x80\x69" \
                       b"\x99\x36\x37\x71\x0f\x92\x32\x18" \
                       b"\xe7\x73\x8a\x73\xc6\xdf\xb1\xb7" \
                       b"\xfb\xf2\xaf\xa3\x84\xaf\x69\x12" \
                       b"\xe0\xf0\x87\xc7\xb4\x32\x3f\x56" \
                       b"\xfc\xba\x10\x88\x62\xfb\xa1\x69" \
                       b"\x30\x22\x89\x04\xdd\x51\xa9\x8e" \
                       b"\x3e\x7a\x32\x79\x17\x1c\x4f\x47" \
                       b"\x2b\xf1\xf9\xf4\x1e\x35\x09\xfa" \
                       b"\x93\x02\x03\x01\x00\x01"
        public_key = b"\x30\x82\x01\x0a\x02\x82\x01\x01" \
                     b"\x00\x9d\xb9\xd2\xd9\x76\x57\x8b" \
                     b"\x22\x3a\x25\xc5\x4d\xd0\xef\xa9" \
                     b"\x29\x1e\x7b\x4e\xec\x5e\x13\x00" \
                     b"\x06\x4e\xba\xad\xf3\x0b\x84\xd9" \
                     b"\x37\xaf\x2f\x2c\x65\x9e\x9b\xaf" \
                     b"\x47\xf9\x63\x63\x63\x9f\x7f\x9c" \
                     b"\xdd\x3e\x85\x96\xb3\x46\x33\x42" \
                     b"\x0a\x0c\x6d\xee\x67\x78\xa9\xf0" \
                     b"\x73\xdc\x02\x82\x30\x61\x49\x29" \
                     b"\xf7\x55\xb3\x43\x68\x40\xfc\xa1" \
                     b"\x72\xd9\xca\xf3\x1a\xa4\x99\x9d" \
                     b"\x52\xc3\x98\x1a\x8a\x27\xf8\x8b" \
                     b"\xb8\xe3\xdc\x1a\x82\x2b\x92\x1e" \
                     b"\xbc\x50\x8c\xa3\x6a\x1c\x25\x2f" \
                     b"\x39\xb5\x90\xc5\x56\x19\x01\x03" \
                     b"\x19\xfb\x01\xc9\x16\x7a\x66\x7c" \
                     b"\x78\x64\x7b\xd4\xe6\x40\x65\xdb" \
                     b"\x09\x21\x8e\x8b\xa5\x99\xac\xb3" \
                     b"\x92\xf2\x46\xf3\xa2\x88\x0b\x48" \
                     b"\x83\x3f\xbf\x74\xaf\x03\xd4\xf7" \
                     b"\x50\x52\x3f\xea\xde\xf1\x33\x04" \
                     b"\xc2\xb4\x3b\x8e\x54\xa2\x57\x26" \
                     b"\x5a\x66\x28\x64\xfb\xfd\x09\x21" \
                     b"\xbe\xbd\x93\x97\xc2\x70\x80\x69" \
                     b"\x99\x36\x37\x71\x0f\x92\x32\x18" \
                     b"\xe7\x73\x8a\x73\xc6\xdf\xb1\xb7" \
                     b"\xfb\xf2\xaf\xa3\x84\xaf\x69\x12" \
                     b"\xe0\xf0\x87\xc7\xb4\x32\x3f\x56" \
                     b"\xfc\xba\x10\x88\x62\xfb\xa1\x69" \
                     b"\x30\x22\x89\x04\xdd\x51\xa9\x8e" \
                     b"\x3e\x7a\x32\x79\x17\x1c\x4f\x47" \
                     b"\x2b\xf1\xf9\xf4\x1e\x35\x09\xfa" \
                     b"\x93\x02\x03\x01\x00\x01"
        credssp._verify_public_keys(nonce, response_key, public_key)

    def test_verify_pub_key_old_mismatch(self):
        credssp = CredSSPContext("", "", "")
        nonce = None
        response_key = b"\x30\x82\x01\x0a\x02\x82\x01\x01" \
                       b"\x00\x9d\xb9\xd2\xd9\x76\x57\x8b" \
                       b"\x22\x3a\x25\xc5\x4d\xd0\xef\xa9" \
                       b"\x29\x1e\x7b\x4e\xec\x5e\x13\x00" \
                       b"\x06\x4e\xba\xad\xf3\x0b\x84\xd9" \
                       b"\x37\xaf\x2f\x2c\x65\x9e\x9b\xaf" \
                       b"\x47\xf9\x63\x63\x63\x9f\x7f\x9c" \
                       b"\xdd\x3e\x85\x96\xb3\x46\x33\x42" \
                       b"\x0a\x0c\x6d\xee\x67\x78\xa9\xf0" \
                       b"\x73\xdc\x02\x82\x30\x61\x49\x29" \
                       b"\xf7\x55\xb3\x43\x68\x40\xfc\xa1" \
                       b"\x72\xd9\xca\xf3\x1a\xa4\x99\x9d" \
                       b"\x52\xc3\x98\x1a\x8a\x27\xf8\x8b" \
                       b"\xb8\xe3\xdc\x1a\x82\x2b\x92\x1e" \
                       b"\xbc\x50\x8c\xa3\x6a\x1c\x25\x2f" \
                       b"\x39\xb5\x90\xc5\x56\x19\x01\x03" \
                       b"\x19\xfb\x01\xc9\x16\x7a\x66\x7c" \
                       b"\x78\x64\x7b\xd4\xe6\x40\x65\xdb" \
                       b"\x09\x21\x8e\x8b\xa5\x99\xac\xb3" \
                       b"\x92\xf2\x46\xf3\xa2\x88\x0b\x48" \
                       b"\x83\x3f\xbf\x74\xaf\x03\xd4\xf7" \
                       b"\x50\x52\x3f\xea\xde\xf1\x33\x04" \
                       b"\xc2\xb4\x3b\x8e\x54\xa2\x57\x26" \
                       b"\x5a\x66\x28\x64\xfb\xfd\x09\x21" \
                       b"\xbe\xbd\x93\x97\xc2\x70\x80\x69" \
                       b"\x99\x36\x37\x71\x0f\x92\x32\x18" \
                       b"\xe7\x73\x8a\x73\xc6\xdf\xb1\xb7" \
                       b"\xfb\xf2\xaf\xa3\x84\xaf\x69\x12" \
                       b"\xe0\xf0\x87\xc7\xb4\x32\x3f\x56" \
                       b"\xfc\xba\x10\x88\x62\xfb\xa1\x69" \
                       b"\x30\x22\x89\x04\xdd\x51\xa9\x8e" \
                       b"\x3e\x7a\x32\x79\x17\x1c\x4f\x47" \
                       b"\x2b\xf1\xf9\xf4\x1e\x35\x09\xfa" \
                       b"\x93\x02\x03\x01\x00\x01"
        public_key = b"\x30\x82\x01\x0a\x02\x82\x01\x01" \
                     b"\x00\x9d\xb9\xd2\xd9\x76\x57\x8b" \
                     b"\x22\x3a\x25\xc5\x4d\xd0\xef\xa9" \
                     b"\x29\x1e\x7b\x4e\xec\x5e\x13\x00" \
                     b"\x06\x4e\xba\xad\xf3\x0b\x84\xd9" \
                     b"\x37\xaf\x2f\x2c\x65\x9e\x9b\xaf" \
                     b"\x47\xf9\x63\x63\x63\x9f\x7f\x9c" \
                     b"\xdd\x3e\x85\x96\xb3\x46\x33\x42" \
                     b"\x0a\x0c\x6d\xee\x67\x78\xa9\xf0" \
                     b"\x73\xdc\x02\x82\x30\x61\x49\x29" \
                     b"\xf7\x55\xb3\x43\x68\x40\xfc\xa1" \
                     b"\x72\xd9\xca\xf3\x1a\xa4\x99\x9d" \
                     b"\x52\xc3\x98\x1a\x8a\x27\xf8\x8b" \
                     b"\xb8\xe3\xdc\x1a\x82\x2b\x92\x1e" \
                     b"\xbc\x50\x8c\xa3\x6a\x1c\x25\x2f" \
                     b"\x39\xb5\x90\xc5\x56\x19\x01\x03" \
                     b"\x19\xfb\x01\xc9\x16\x7a\x66\x7c" \
                     b"\x78\x64\x7b\xd4\xe6\x40\x65\xdb" \
                     b"\x09\x21\x8e\x8b\xa5\x99\xac\xb3" \
                     b"\x92\xf2\x46\xf3\xa2\x88\x0b\x48" \
                     b"\x83\x3f\xbf\x74\xaf\x03\xd4\xf7" \
                     b"\x50\x52\x3f\xea\xde\xf1\x33\x04" \
                     b"\xc2\xb4\x3b\x8e\x54\xa2\x57\x26" \
                     b"\x5a\x66\x28\x64\xfb\xfd\x09\x21" \
                     b"\xbe\xbd\x93\x97\xc2\x70\x80\x69" \
                     b"\x99\x36\x37\x71\x0f\x92\x32\x18" \
                     b"\xe7\x73\x8a\x73\xc6\xdf\xb1\xb7" \
                     b"\xfb\xf2\xaf\xa3\x84\xaf\x69\x12" \
                     b"\xe0\xf0\x87\xc7\xb4\x32\x3f\x56" \
                     b"\xfc\xba\x10\x88\x62\xfb\xa1\x69" \
                     b"\x30\x22\x89\x04\xdd\x51\xa9\x8e" \
                     b"\x3e\x7a\x32\x79\x17\x1c\x4f\x47" \
                     b"\x2b\xf1\xf9\xf4\x1e\x35\x09\xfa" \
                     b"\x93\x02\x03\x01\x00\x01"
        with pytest.raises(AuthenticationException) as exc:
            credssp._verify_public_keys(nonce, response_key, public_key)
        assert str(exc.value) == "Could not verify key sent from the " \
                                 "server, potential man in the middle attack"

    def test_verify_pub_key_new(self):
        credssp = CredSSPContext("", "", "")
        nonce = b"\x02\xce\xee\x0c\xdf\x03\x49\x30" \
                b"\xc7\x55\xd7\xdd\x4a\x8a\xda\xaf" \
                b"\xeb\x7e\x78\x9d\x86\x9c\xb2\xb8" \
                b"\xd7\x9f\x71\x0c\xe2\x83\x72\x4d"
        response_key = b"\xde\x4f\xc6\xa6\xba\xb2\x0e\xc5" \
                       b"\x29\x6e\x8d\xe5\xe7\x84\xc7\x11" \
                       b"\xef\xb8\xe4\xd0\xc3\x39\x4f\x4b" \
                       b"\xb9\x64\xbd\xff\xf1\xc0\xb8\xc2"
        public_key = b"\x30\x82\x01\x0a\x02\x82\x01\x01" \
                     b"\x00\x9d\xb9\xd2\xd9\x76\x57\x8b" \
                     b"\x22\x3a\x25\xc5\x4d\xd0\xef\xa9" \
                     b"\x29\x1e\x7b\x4e\xec\x5e\x13\x00" \
                     b"\x06\x4e\xba\xad\xf3\x0b\x84\xd9" \
                     b"\x37\xaf\x2f\x2c\x65\x9e\x9b\xaf" \
                     b"\x47\xf9\x63\x63\x63\x9f\x7f\x9c" \
                     b"\xdd\x3e\x85\x96\xb3\x46\x33\x42" \
                     b"\x0a\x0c\x6d\xee\x67\x78\xa9\xf0" \
                     b"\x73\xdc\x02\x82\x30\x61\x49\x29" \
                     b"\xf7\x55\xb3\x43\x68\x40\xfc\xa1" \
                     b"\x72\xd9\xca\xf3\x1a\xa4\x99\x9d" \
                     b"\x52\xc3\x98\x1a\x8a\x27\xf8\x8b" \
                     b"\xb8\xe3\xdc\x1a\x82\x2b\x92\x1e" \
                     b"\xbc\x50\x8c\xa3\x6a\x1c\x25\x2f" \
                     b"\x39\xb5\x90\xc5\x56\x19\x01\x03" \
                     b"\x19\xfb\x01\xc9\x16\x7a\x66\x7c" \
                     b"\x78\x64\x7b\xd4\xe6\x40\x65\xdb" \
                     b"\x09\x21\x8e\x8b\xa5\x99\xac\xb3" \
                     b"\x92\xf2\x46\xf3\xa2\x88\x0b\x48" \
                     b"\x83\x3f\xbf\x74\xaf\x03\xd4\xf7" \
                     b"\x50\x52\x3f\xea\xde\xf1\x33\x04" \
                     b"\xc2\xb4\x3b\x8e\x54\xa2\x57\x26" \
                     b"\x5a\x66\x28\x64\xfb\xfd\x09\x21" \
                     b"\xbe\xbd\x93\x97\xc2\x70\x80\x69" \
                     b"\x99\x36\x37\x71\x0f\x92\x32\x18" \
                     b"\xe7\x73\x8a\x73\xc6\xdf\xb1\xb7" \
                     b"\xfb\xf2\xaf\xa3\x84\xaf\x69\x12" \
                     b"\xe0\xf0\x87\xc7\xb4\x32\x3f\x56" \
                     b"\xfc\xba\x10\x88\x62\xfb\xa1\x69" \
                     b"\x30\x22\x89\x04\xdd\x51\xa9\x8e" \
                     b"\x3e\x7a\x32\x79\x17\x1c\x4f\x47" \
                     b"\x2b\xf1\xf9\xf4\x1e\x35\x09\xfa" \
                     b"\x93\x02\x03\x01\x00\x01"
        credssp._verify_public_keys(nonce, response_key, public_key)

    def test_verify_pub_key_new_mismatch(self):
        credssp = CredSSPContext("", "", "")
        nonce = b"\x02\xce\xee\x0c\xdf\x03\x49\x30" \
                b"\xc7\x55\xd7\xdd\x4a\x8a\xda\xaf" \
                b"\xeb\x7e\x78\x9d\x86\x9c\xb2\xb8" \
                b"\xd7\x9f\x71\x0c\xe2\x83\x72\x4d"
        response_key = b"\xdf\x4f\xc6\xa6\xba\xb2\x0e\xc5" \
                       b"\x29\x6e\x8d\xe5\xe7\x84\xc7\x11" \
                       b"\xef\xb8\xe4\xd0\xc3\x39\x4f\x4b" \
                       b"\xb9\x64\xbd\xff\xf1\xc0\xb8\xc2"
        public_key = b"\x30\x82\x01\x0a\x02\x82\x01\x01" \
                     b"\x00\x9d\xb9\xd2\xd9\x76\x57\x8b" \
                     b"\x22\x3a\x25\xc5\x4d\xd0\xef\xa9" \
                     b"\x29\x1e\x7b\x4e\xec\x5e\x13\x00" \
                     b"\x06\x4e\xba\xad\xf3\x0b\x84\xd9" \
                     b"\x37\xaf\x2f\x2c\x65\x9e\x9b\xaf" \
                     b"\x47\xf9\x63\x63\x63\x9f\x7f\x9c" \
                     b"\xdd\x3e\x85\x96\xb3\x46\x33\x42" \
                     b"\x0a\x0c\x6d\xee\x67\x78\xa9\xf0" \
                     b"\x73\xdc\x02\x82\x30\x61\x49\x29" \
                     b"\xf7\x55\xb3\x43\x68\x40\xfc\xa1" \
                     b"\x72\xd9\xca\xf3\x1a\xa4\x99\x9d" \
                     b"\x52\xc3\x98\x1a\x8a\x27\xf8\x8b" \
                     b"\xb8\xe3\xdc\x1a\x82\x2b\x92\x1e" \
                     b"\xbc\x50\x8c\xa3\x6a\x1c\x25\x2f" \
                     b"\x39\xb5\x90\xc5\x56\x19\x01\x03" \
                     b"\x19\xfb\x01\xc9\x16\x7a\x66\x7c" \
                     b"\x78\x64\x7b\xd4\xe6\x40\x65\xdb" \
                     b"\x09\x21\x8e\x8b\xa5\x99\xac\xb3" \
                     b"\x92\xf2\x46\xf3\xa2\x88\x0b\x48" \
                     b"\x83\x3f\xbf\x74\xaf\x03\xd4\xf7" \
                     b"\x50\x52\x3f\xea\xde\xf1\x33\x04" \
                     b"\xc2\xb4\x3b\x8e\x54\xa2\x57\x26" \
                     b"\x5a\x66\x28\x64\xfb\xfd\x09\x21" \
                     b"\xbe\xbd\x93\x97\xc2\x70\x80\x69" \
                     b"\x99\x36\x37\x71\x0f\x92\x32\x18" \
                     b"\xe7\x73\x8a\x73\xc6\xdf\xb1\xb7" \
                     b"\xfb\xf2\xaf\xa3\x84\xaf\x69\x12" \
                     b"\xe0\xf0\x87\xc7\xb4\x32\x3f\x56" \
                     b"\xfc\xba\x10\x88\x62\xfb\xa1\x69" \
                     b"\x30\x22\x89\x04\xdd\x51\xa9\x8e" \
                     b"\x3e\x7a\x32\x79\x17\x1c\x4f\x47" \
                     b"\x2b\xf1\xf9\xf4\x1e\x35\x09\xfa" \
                     b"\x93\x02\x03\x01\x00\x01"
        with pytest.raises(AuthenticationException) as exc:
            credssp._verify_public_keys(nonce, response_key, public_key)
        assert str(exc.value) == "Could not verify key sent from the " \
                                 "server, potential man in the middle attack"

    def test_get_encrypted_credentials(self):
        class FakeContext(object):
            def __init__(self):
                self.domain = "domain"
                self.username = "username"
                self.password = "password"

            def wrap(self, data):
                return data + (b"\x00" * 4)

        context = FakeContext()
        credssp = CredSSPContext("", "", "")
        expected = b"\x30\x52" \
                   b"\xa0\x03" \
                   b"\x02\x01" \
                   b"\x06" \
                   b"\xa2\x4b" \
                   b"\x04\x49" \
                   b"\x30\x43" \
                   b"\xa0\x03" \
                   b"\x02\x01" \
                   b"\x01" \
                   b"\xa1\x3c" \
                   b"\x04\x3a" \
                   b"\x30\x38" \
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
                   b"\x77\x00\x6f\x00\x72\x00\x64\x00" \
                   b"\x00\x00\x00\x00"
        actual = credssp._get_encrypted_credentials(context)
        assert actual == expected


class TestHttpCredSSPAuth(object):

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
        pattern = re.compile("CredSSP ([^,\s]*)$", re.I)
        response = requests.Response()
        response.headers['www-authenticate'] = "CredSSP YWJj"
        expected = b"abc"
        actual = HttpCredSSPAuth._get_credssp_token(response, pattern,
                                                    "step 1")
        assert actual == expected

    def test_get_credssp_token_fail_no_header(self):
        pattern = re.compile("CredSSP ([^,\s]*)$", re.I)
        response = requests.Response()
        with pytest.raises(AuthenticationException) as exc:
            HttpCredSSPAuth._get_credssp_token(response, pattern, "step 1")
        assert str(exc.value) == "Server did not response with a CredSSP " \
                                 "token after step step 1 - actual ''"

    def test_get_credssp_token_fail_no_credssp_token(self):
        pattern = re.compile("CredSSP ([^,\s]*)$", re.I)
        response = requests.Response()
        response.headers['www-authenticate'] = "NTLM YWJj"
        with pytest.raises(AuthenticationException) as exc:
            HttpCredSSPAuth._get_credssp_token(response, pattern, "step 1")
        assert str(exc.value) == "Server did not response with a CredSSP " \
                                 "token after step step 1 - actual 'NTLM YWJj'"

    def test_assert_warning_tls_context(self):
        class CredSSPContextTest(object):
            def __init__(self, value):
                self.tls_context = value

        credssp = HttpCredSSPAuth("", "")
        credssp.contexts['first'] = CredSSPContextTest("a")
        warnings.simplefilter("always")

        with warnings.catch_warnings(record=True) as w:
            assert credssp.tls_context == "a"
            assert len(w) == 1
            assert w[0].category == DeprecationWarning
            assert str(w[0].message) == \
                "Deprecated property tls_context, this property should be " \
                "accessed using the host context, " \
                "credssp['hostname'].tls_context"

    def test_assert_warning_tls_connection(self):
        class CredSSPContextTest(object):
            def __init__(self, value):
                self.tls_connection = value

        credssp = HttpCredSSPAuth("", "")
        credssp.contexts['first'] = CredSSPContextTest("a")
        warnings.simplefilter("always")

        with warnings.catch_warnings(record=True) as w:
            assert credssp.tls_connection == "a"
            assert len(w) == 1
            assert w[0].category == DeprecationWarning
            assert str(w[0].message) == \
                "Deprecated property tls_connection, this property " \
                "should be accessed using the host context, " \
                "credssp['hostname'].tls_connection"

    def test_assert_warning_cipher_negotiated(self):
        class CredSSPContextTest(object):
            def __init__(self, value):
                class TlsConnection(object):
                    def __init__(self, value):
                        self.value = value

                    def get_cipher_name(self):
                        return self.value

                self.tls_connection = TlsConnection(value)

        credssp = HttpCredSSPAuth("", "")
        credssp.contexts['first'] = CredSSPContextTest("a")
        warnings.simplefilter("always")

        with warnings.catch_warnings(record=True) as w:
            assert credssp.cipher_negotiated == "a"
            assert len(w) == 1
            assert w[0].category == DeprecationWarning
            assert str(w[0].message) == \
                "Deprecated property cipher_negotiated, this property " \
                "should be accessed using the host context, " \
                "credssp['hostname'].tls_connection.get_cipher_name()"

    def test_assert_warning_wrap(self):
        class CredSSPContextTest(object):
            def __init__(self, value):
                self.value = value

            def wrap(self, data):
                return self.value

        credssp = HttpCredSSPAuth("", "")
        credssp.contexts['first'] = CredSSPContextTest(b"a")
        warnings.simplefilter("always")

        with warnings.catch_warnings(record=True) as w:
            assert credssp.wrap(b"") == b"a"
            assert len(w) == 1
            assert w[0].category == DeprecationWarning
            assert str(w[0].message) == \
                "Deprecated function, wrap should be accessed using the " \
                "host context wrap function, credssp['hostname'].wrap()"

    def test_assert_warning_unwrap(self):
        class CredSSPContextTest(object):
            def __init__(self, value):
                self.value = value

            def unwrap(self, data):
                return self.value

        credssp = HttpCredSSPAuth("", "")
        credssp.contexts['first'] = CredSSPContextTest(b"a")
        warnings.simplefilter("always")

        with warnings.catch_warnings(record=True) as w:
            assert credssp.unwrap(b"") == b"a"
            assert len(w) == 1
            assert w[0].category == DeprecationWarning
            assert str(w[0].message) == \
                "Deprecated function, unwrap should be accessed using the " \
                "host context unwrap function, credssp['hostname'].unwrap()"


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

        with pytest.raises(NTStatusException) as exc:
            self._send_request(test_url, runner[1], "fakepass")
        assert str(exc.value) == "Received error status from the server: " \
                                 "(3221225581) STATUS_LOGON_FAILURE 0xc000006d"

    def test_credssp_minimum_client_fail(self, runner):
        test_url = "https://%s:5986/wsman" % runner[0]

        with pytest.raises(AuthenticationException) as exc:
            self._send_request(test_url, runner[1], runner[2],
                               minimum_version=100)
        assert "did not meet the minimum requirements of 10" in str(exc.value)

    def _send_request(self, url, username, password, minimum_version=2):
        """
        Sends a request to the url with the credentials specified. Will also
        try send an encrypted config request and return the decrypted response
        """
        from urllib3.exceptions import InsecureRequestWarning
        warnings.simplefilter('ignore', category=InsecureRequestWarning)

        session = requests.Session()
        session.verify = False
        session.auth = HttpCredSSPAuth(username, password,
                                       auth_mechanism='ntlm',
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
        encrypted_message = context.wrap(config_message.encode('utf-8'))
        trailer_length = self._get_trailer_length(
            len(config_message), context.tls_connection.get_cipher_name()
        )

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
        decrypted_response = context.unwrap(encrypted_payload[4:])

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


class TestSPNEGO(object):

    def test_spnego_auth_mechanism_auto(self):
        spnego = SPNEGO("", "", "", "auto")
        # while Kerberos should be in the mechs, we only add that in if the
        # init context was successful in the first step
        assert spnego.mechs == [SPNEGOMechs.NTLMSSP]
        assert spnego.try_kerberos

    def test_spnego_auth_mechanism_ntlm(self):
        spnego = SPNEGO("", "", "", "ntlm")
        assert spnego.mechs == [SPNEGOMechs.NTLMSSP]
        assert not spnego.try_kerberos

    def test_spnego_invalid_auth_mechanism(self):
        with pytest.raises(InvalidConfigurationException) as exc:
            SPNEGO("", "", "", "fake")
        assert str(exc.value) == "Invalid auth mechanism value fake, must " \
                                 "be auto, ntlm or kerberos"


class TestNTLMContext(object):

    def test_auth_step(self):
        ntlm = NTLMContext("hostname", "username", "password")
        assert ntlm.hostname == "hostname"
        assert ntlm.domain == ""
        assert ntlm.username == "username"
        assert ntlm.password == "password"

        challenge_token = b'\x4E\x54\x4C\x4D\x53\x53\x50\x00' \
                          b'\x02\x00\x00\x00\x04\x00\x04\x00' \
                          b'\x38\x00\x00\x00\x36\x82\x89\xE2' \
                          b'\x45\x80\xF2\xD5\xB4\xF3\xED\x50' \
                          b'\x00\x00\x00\x00\x00\x00\x00\x00' \
                          b'\xB2\x00\xB2\x00\x3C\x00\x00\x00' \
                          b'\x06\x01\xB1\x1D\x00\x00\x00\x0F' \
                          b'\x43\x4F\x52\x50\x02\x00\x08\x00' \
                          b'\x43\x00\x4F\x00\x52\x00\x50\x00' \
                          b'\x01\x00\x1A\x00\x43\x00\x4F\x00' \
                          b'\x4D\x00\x50\x00\x55\x00\x54\x00' \
                          b'\x45\x00\x52\x00\x48\x00\x4F\x00' \
                          b'\x53\x00\x54\x00\x31\x00\x04\x00' \
                          b'\x1E\x00\x63\x00\x6F\x00\x72\x00' \
                          b'\x70\x00\x2E\x00\x6F\x00\x72\x00' \
                          b'\x67\x00\x2E\x00\x63\x00\x6F\x00' \
                          b'\x6D\x00\x2E\x00\x61\x00\x75\x00' \
                          b'\x03\x00\x3A\x00\x43\x00\x4F\x00' \
                          b'\x4D\x00\x50\x00\x55\x00\x54\x00' \
                          b'\x45\x00\x52\x00\x48\x00\x4F\x00' \
                          b'\x53\x00\x54\x00\x31\x00\x2E\x00' \
                          b'\x63\x00\x6F\x00\x72\x00\x70\x00' \
                          b'\x2E\x00\x6F\x00\x72\x00\x67\x00' \
                          b'\x2E\x00\x63\x00\x6F\x00\x6D\x00' \
                          b'\x2E\x00\x61\x00\x75\x00\x05\x00' \
                          b'\x14\x00\x6F\x00\x72\x00\x67\x00' \
                          b'\x2E\x00\x63\x00\x6F\x00\x6D\x00' \
                          b'\x2E\x00\x61\x00\x75\x00\x07\x00' \
                          b'\x08\x00\xC5\xBE\x86\x1B\x94\x04' \
                          b'\xD2\x01\x00\x00\x00\x00'
        msg1 = ntlm.step()
        assert not ntlm.complete
        assert isinstance(msg1, bytes)
        assert msg1[:9] == b"NTLMSSP\x00\x01"

        msg3 = ntlm.step(challenge_token)
        assert ntlm.complete
        assert isinstance(msg3, bytes)
        assert msg3[:9] == b"NTLMSSP\x00\x03"

        # the sign message and encrypted message should have different seq
        # numbers
        data = b"\x01\x02\x03\x04"
        sign_msg = ntlm.sign(data)
        enc_msg = ntlm.wrap(data)
        assert sign_msg != enc_msg
        assert sign_msg != data
        assert enc_msg != data
        import binascii

        # 0-4 is NTLM sig == 01 00 00 00 , 12:16 is the sequence number
        assert sign_msg[:4] == b"\x01\x00\x00\x00"
        assert sign_msg[12:16] == b"\x00\x00\x00\x00"
        assert enc_msg[:4] == b"\x01\x00\x00\x00"
        assert enc_msg[12:16] == b"\x01\x00\x00\x00"

    def test_ntlm_username_upn(self):
        ntlm = NTLMContext("", "username@DOMAIN.LOCAL", "password")
        assert ntlm.domain == ""
        assert ntlm.username == "username@DOMAIN.LOCAL"
        assert ntlm.password == "password"

    def test_ntlm_netlogon(self):
        ntlm = NTLMContext("", "DOMAIN\\username", "password")
        assert ntlm.domain == "DOMAIN"
        assert ntlm.username == "username"
        assert ntlm.password == "password"


class TestGSSApiContext(object):

    def test_gssapi_properties(self):
        # not much we can do here apart from verifying it doesn't change the
        # username
        gssapi = GSSApiContext("hostname", "username@DOMAIN.LOCAL", "password")
        assert gssapi.hostname == "hostname"
        assert gssapi.domain == ""
        assert gssapi.username == "username@DOMAIN.LOCAL"
        assert gssapi.password == "password"
        assert not gssapi.complete
