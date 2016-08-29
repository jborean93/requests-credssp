import struct

ASN1_TYPE_INTEGER = 0x02
ASN1_TYPE_OCTET_STRING = 0x04
ASN1_TYPE_SEQUENCE = 0x30

def asn1encode(value):
    """
    This method will create the type/length/value triplet for the type and value passed in.

    :param type: The ASN.1 type in a hexadecimal format
    :param value: The value to encode in ASN.1 format
    :return: An ASN.1 encoded structure of the value and type passed in
    """
    value_length = len(value)

    # Checks whether the length will be in the short or long form
    if value_length >= 0 and value_length <= 0x7f:
        length = struct.pack('B', value_length)
    elif value_length >= 0x80 and value_length <= 0xff:
        length = struct.pack('BB', 0x81, value_length)
    elif value_length >= 0x100 and value_length <= 0xffff:
        length = struct.pack('!BH', 0x82, value_length)
    elif value_length >= 0x10000 and value_length <= 0xffffff:
        length = struct.pack('!BBH', 0x83, value_length >> 16, value_length & 0xffff)
    elif value_length >= 0x1000000 and value_length <= 0xffffffff:
        length = struct.pack('!BL', 0x84, value_length)
    else:
        raise Exception('Could not determine the ASN length')

    asn = length + value
    return str(asn)

def asn1decode(value):
    """
    This method will decode the ASN.1 structure returned from the server

    :param value: The ASN.1 structure to decode
    :return: The value and the total length of the ASN.1 value
    """
    field_length = struct.unpack('B', value[:1])[0]
    value = value[1:]

    # Check if the length is in the definite short form or definite long form
    if field_length == 0x81:
        length_padding = struct.calcsize('B')
        field_length = struct.unpack('B', value[:length_padding])[0]
        value = value[length_padding:]
        asn = value[:field_length]

    elif field_length == 0x82:
        length_padding = struct.calcsize('H')
        field_length = struct.unpack('!H', value[:length_padding])[0]
        value = value[length_padding:]
        asn = value[:field_length]

    elif field_length == 0x83:
        length_padding = struct.calcsize('B') + struct.calcsize('!H')
        field_length1, field_length2 = struct.unpack('!BH', value[:length_padding])
        value = value[length_padding:]
        asn = value[:field_length1 << 16 + field_length2]

    elif field_length == 0x84:
        length_padding = struct.calcsize('!L')
        field_length = struct.unpack('!L', value[:length_padding])[0]
        value = value[length_padding:]
        asn = value[:field_length]

    else:
        # ASN.1 field length is in the short form
        length_padding = 0
        asn = value[:field_length]

    # Recalculate the field length by getting the asn value, the length padding plus the length byte
    field_length = len(asn) + length_padding + 1

    return asn, field_length


def get_asn1_field(field_info):
    """
    This method takes in the field_info structure for a field and generates the ASN.1 value to send to the server.

    :param field_info: A ASN1Field object that has the field metadata and data
    :return: ASN.1 field value to add to the final sequence structure
    """
    field_value = field_info.value
    if field_value is None:
        if field_info.optional is False:
            raise Exception("Cannot get data for mandatory field %s, value is not set" % field_info.field_name)
        else:
            return ''

    sequence = struct.pack('B', field_info.sequence)
    type = struct.pack('B', field_info.type)
    value = asn1encode(field_value)

    field = sequence + asn1encode(type + value)
    return field

def parse_asn1_field(data, field_info):
    """
    This method will take in the decoded ASN.1 data and parse the next field in the sequence. It will update the
    field_info map with the value that is parsed.

    :param data: The decoded ASN.1 data field to parse
    :param field_info: A ASN1Field object that has the field metadata and data
    :return: The total bytes of the value, used to move the offset of the full ASN.1 data structure
    """
    field_name = field_info.field_name
    expected_sequence_byte = field_info.sequence
    expected_type_byte = field_info.type

    # Check that the sequence in the data passes in matches what we expect
    sequence_byte = struct.unpack('B', data[:1])[0]
    if sequence_byte != expected_sequence_byte:
        raise Exception(
            "Expecting sequence (%x) for %s, was (%x)" % (expected_sequence_byte, field_name, sequence_byte))

    # Decode the rest of the data for that field
    decoded_data, total_bytes = asn1decode(data[1:])

    # Check the field type matches what we expect
    type_byte = struct.unpack('B', decoded_data[:1])[0]
    if type_byte != expected_type_byte:
        raise Exception("Expecting %s type to be (%x), was (%x)" % (field_name, expected_type_byte, type_byte))

    # After checking the field type, decode the rest of the field data
    field_data, ignore = asn1decode(decoded_data[1:])
    field_info.value = field_data

    # Return the field value and the total bytes of the field + 1 to include the sequence byte
    return total_bytes + 1

class ASN1Field(object):
    def __init__(self, field_name, sequence, type, optional=False):
        """
        Generic ASN.1 field object to store common values for different field. Will set the value field to None on
        initialisation

        :param field_name: The human friendly name of the field, used in exception messages
        :param sequence: The sequence number of the field when used in a sequence
        :param type: The ASN.1 field type of the field
        :param optional: Whether the field is option (True) or mandatory (False)
        """
        self.field_name = field_name
        self.sequence = sequence
        self.type = type
        self.optional = optional
        self.value = None
