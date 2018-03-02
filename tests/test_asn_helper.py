from requests_credssp.asn_helper import pack_asn1, unpack_asn1


class TestAsnPackers(object):
    def test_pack_short_form(self):
        test_data = b'1'
        expected = b"\x01\x31"
        actual = pack_asn1(test_data)
        assert actual == expected

    def test_pack_long_form_one_octet(self):
        test_data = b'1' * 128
        expected_data = b"\x31" * 128
        expected = b"\x81\x80" + expected_data
        actual = pack_asn1(test_data)
        assert actual == expected

    def test_pack_unpack_long_form_two_octets(self):
        test_data = b'1' * 256
        expected_data = b"\x31" * 256
        expected = b"\x82\x01\x00" + expected_data
        actual = pack_asn1(test_data)
        assert actual == expected

    def test_pack_unpack_long_form_three_octets(self):
        test_data = b'1' * 65536
        expected_data = b"\x31" * 65536
        expected = b"\x83\x01\x00\x00" + expected_data
        actual = pack_asn1(test_data)
        assert actual == expected

    def test_pack_unpack_long_form_four_octets(self):
        test_data = b'1' * 16777216
        expected_data = b"\x31" * 16777216
        expected = b"\x84\x01\x00\x00\x00" + expected_data
        actual = pack_asn1(test_data)
        assert actual == expected

    def test_unpack_short_form(self):
        test_data = b"\x02\x01\x31"
        expected_data = b'1'
        expected_octets = 3
        actual_data, actual_octets = unpack_asn1(test_data)
        assert actual_data == expected_data
        assert actual_octets == expected_octets

    def test_unpack_long_form_one_octet(self):
        test_data = b'\x02\x81\x80' + b'\x31' * 128
        expected_data = b'1' * 128
        expected_octets = 131
        actual_data, actual_octets = unpack_asn1(test_data)
        assert actual_data == expected_data
        assert actual_octets == expected_octets

    def test_unpack_long_form_two_octets(self):
        test_data = b'\x02\x82\x01\x00' + b'\x31' * 256
        expected_data = b'1' * 256
        expected_octets = 260
        actual_data, actual_octets = unpack_asn1(test_data)
        assert actual_data == expected_data
        assert actual_octets == expected_octets

    def test_unpack_long_form_three_octets(self):
        test_data = b'\x02\x83\x01\x00\x00' + b'\x31' * 65536
        expected_data = b'1' * 65536
        expected_octets = 65541
        actual_data, actual_octets = unpack_asn1(test_data)
        assert actual_data == expected_data
        assert actual_octets == expected_octets

    def test_unpack_long_form_fource_octets(self):
        test_data = b'\x02\x84\x01\x00\x00\x00' + b'\x31' * 16777216
        expected_data = b'1' * 16777216
        expected_octets = 16777222
        actual_data, actual_octets = unpack_asn1(test_data)
        assert actual_data == expected_data
        assert actual_octets == expected_octets
