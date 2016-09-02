import unittest2 as unittest

from requests_credssp.asn_helper import pack_asn1, unpack_asn1
from tests.utils import hex_to_byte

class TestAsnPackers(unittest.TestCase):
    def test_pack_short_form(self):
        test_data = b'1'
        expected = hex_to_byte('01 31')

        actual = pack_asn1(test_data)

        assert actual == expected

    def test_pack_long_form_one_octet(self):
        test_data = b'1' * 128

        expected_data = hex_to_byte('31') * 128
        expected = hex_to_byte('81 80') + expected_data

        actual = pack_asn1(test_data)

        assert actual == expected

    def test_pack_unpack_long_form_two_octets(self):
        test_data = b'1' * 256

        expected_data = hex_to_byte('31') * 256
        expected = hex_to_byte('82 01 00') + expected_data

        actual = pack_asn1(test_data)

        assert actual == expected


    def test_pack_unpack_long_form_three_octets(self):
        test_data = b'1' * 65536

        expected_data = hex_to_byte('31') * 65536
        expected = hex_to_byte('83 01 00 00') + expected_data

        actual = pack_asn1(test_data)

        assert actual == expected

    def test_pack_unpack_long_form_four_octets(self):
        test_data = b'1' * 16777216

        expected_data = hex_to_byte('31') * 16777216
        expected = hex_to_byte('84 01 00 00 00') + expected_data

        actual = pack_asn1(test_data)

        assert actual == expected

    def test_unpack_short_form(self):
        test_data = hex_to_byte('02 01 31')
        expected_data = b'1'
        expected_octets = 3

        actual_data, actual_octets = unpack_asn1(test_data)

        assert actual_data == expected_data
        assert actual_octets == expected_octets

    def test_unpack_long_form_one_octet(self):
        test_data = hex_to_byte('02 81 80') + hex_to_byte('31') * 128
        expected_data = b'1' * 128
        expected_octets = 131

        actual_data, actual_octets = unpack_asn1(test_data)

        assert actual_data == expected_data
        assert actual_octets == expected_octets

    def test_unpack_long_form_two_octets(self):
        test_data = hex_to_byte('02 82 01 00') + hex_to_byte('31') * 256
        expected_data = b'1' * 256
        expected_octets = 260

        actual_data, actual_octets = unpack_asn1(test_data)

        assert actual_data == expected_data
        assert actual_octets == expected_octets

    def test_unpack_long_form_three_octets(self):
        test_data = hex_to_byte('02 83 01 00 00') + hex_to_byte('31') * 65536
        expected_data = b'1' * 65536
        expected_octets = 65541

        actual_data, actual_octets = unpack_asn1(test_data)

        assert actual_data == expected_data
        assert actual_octets == expected_octets

    def test_unpack_long_form_fource_octets(self):
        test_data = hex_to_byte('02 84 01 00 00 00') + hex_to_byte('31') * 16777216
        expected_data = b'1' * 16777216
        expected_octets = 16777222

        actual_data, actual_octets = unpack_asn1(test_data)

        assert actual_data == expected_data
        assert actual_octets == expected_octets
