import struct

from requests_credssp.exceptions import AsnStructureException

ASN1_TYPE_INTEGER = 0x02
ASN1_TYPE_OCTET_STRING = 0x04
ASN1_TYPE_SEQUENCE = 0x30

def is_set(byte, idx):
    # Checks whether the bit set at the idx is on
    mask = 1 << idx
    bit_value = byte & (mask)
    return bit_value != 0

def clear_bit(byte, idx):
    # Turns the bit at the idx to 0
    mask = ~(1 << idx)
    return byte & mask

def pack_asn1(data):
    """
    This method will pack the ASN.1 length and value elements for the value passed in.

    :param data: The data to pack in ASN.1 format
    :return: An ASN.1 encoded structure of the length and value of the data passed in
    """
    value_length = len(data)

    # Checks whether the length will be in the short or long form
    if value_length >= 0 and value_length <= 0x7f:
        length = struct.pack('B', value_length)
    elif value_length >= 0x80 and value_length <= 0xff:
        length = struct.pack('BB', 0x81, value_length)
    elif value_length >= 0x100 and value_length <= 0xffff:
        length = struct.pack('!BH', 0x82, value_length)
    elif value_length >= 0x10000 and value_length <= 0xffffff:
        length = struct.pack('!BBH', 0x83, value_length >> 16, value_length & 0xffff)
    else:
        length = struct.pack('!BL', 0x84, value_length)

    asn = length + data
    return asn

def unpack_asn1(data):
    """
    This method will unpack the ASN.1 structure that is returned from the server.

    :param data: The full ASN.1 structure to unpack including the type octet
    :return: value - The value element unpacked from the ASN.1 structure
    :return: size - Octet size of the type, length and value
    """
    # The type octet is always a single octet for our purposes
    type_octets = 1

    first_length_octet = data[1:2]
    first_length_octet_value = struct.unpack('B', first_length_octet)[0]

    # Check if the first bit is set which means the format is long. (CredSSP data is big endian, i.e. first bit is 7)
    is_long_format = is_set(first_length_octet_value, 7)

    if is_long_format:
        # length definition is set in multiple octets
        # Set the first bit of the first length octet and get it's value. Add an extra value for the first octet
        length_octets = 1 + clear_bit(first_length_octet_value, 7)

        # Initialise empty variables for storing the length value. current_offset is used to multiple each octet value
        value_octets = 0
        current_offset = length_octets - 2

        # Loop through each octet and add it's sum to value_octet_size
        for i in range(length_octets - 1):
            # Get the byte from the relevant octet that is next in the list
            octet_offset = 2 + i
            octet_byte = data[octet_offset:octet_offset + 1]
            raw_value = struct.unpack('B', octet_byte)[0]

            # Multiple the raw value with the relevant power to get real result
            octet_value = raw_value * (256 ** current_offset)

            # Decrement the current_offset so the next octet gets the correct to power result
            current_offset -= 1
            value_octets += octet_value
    else:
        length_octets = 1
        value_octets = first_length_octet_value

    total_octets = type_octets + length_octets + value_octets
    value = data[type_octets + length_octets:total_octets]

    return value, total_octets

def get_context_field(field_info):
    """
    This method will create an ASN.1 field with the relevant context (sequence byte) set by the field_info value.
    This is then used in the full ASN.1 structure and then send to the server for validation.

    :param field_info: A ASN1Field object that has the field metadata and data
    :return: ASN.1 field value to add to the final sequence structure
    """
    field_value = field_info.value
    if field_value is None:
        if field_info.optional is False:
            raise AsnStructureException("Cannot get data for mandatory field %s, value is not set" % field_info.field_name)
        else:
            return b''

    sequence = struct.pack('B', field_info.sequence)
    type = struct.pack('B', field_info.type)
    value = pack_asn1(field_value)

    field = sequence + pack_asn1(type + value)
    return field

def parse_context_field(data, field_info):
    """
    This method will take in the decoded ASN.1 data and parse the next field in the sequence. It will update the
    field_info map with the value that is parsed.

    :param data: The raw ASN.1 data field to parse
    :param field_info: A ASN1Field object that holds the field metadata and data
    :return: The total bytes of the value, for the calling method to know the next offset point
    """
    field_name = field_info.field_name
    expected_sequence_byte = field_info.sequence
    expected_type_byte = field_info.type

    # Check that the sequence in the data passes in matches what we expect
    sequence_byte = struct.unpack('B', data[:1])[0]
    if sequence_byte != expected_sequence_byte:
        raise AsnStructureException(
            "Expecting sequence (%x) for %s, was (%x)" % (expected_sequence_byte, field_name, sequence_byte))

    # Decode the rest of the data for that field
    decoded_data, total_bytes = unpack_asn1(data)

    # Check the field type matches what we expect
    type_byte = struct.unpack('B', decoded_data[:1])[0]
    if type_byte != expected_type_byte:
        raise AsnStructureException(
            "Expecting %s type to be (%x), was (%x)" % (field_name, expected_type_byte, type_byte))

    # After checking the field type, decode the rest of the field data
    field_data, ignore = unpack_asn1(decoded_data)
    field_info.value = field_data

    # Return the field value and the total bytes of the field + 1 to include the sequence byte
    return total_bytes


class ASN1Field(object):
    def __init__(self, field_name, sequence, type, optional=False):
        """
        Generic ASN.1 field object to store common values for fields in a structure. Will set the value field
        to None on initialisation

        :param field_name: The human friendly name of the field, used in exception messages
        :param sequence: The sequence number of the field when used in a sequence (Also known as context)
        :param type: The ASN.1 field type of the field
        :param optional: Whether the field is optional (True) or mandatory (False)
        """
        self.field_name = field_name
        self.sequence = sequence
        self.type = type
        self.optional = optional
        self.value = None


class ASN1Sequence(object):
    """
    Generic methods used by the ASN.1 structures in asn_structures. Generic boilerplate methods that can be
    used to parse data, get the data from the defined fields initialised in the structure.

    """
    def __getitem__(self, item):
        if item in self.fields:
            return self.fields[item]
        else:
            raise AsnStructureException("Illegal field %s in ASN.1 structure" % item)

    def __setitem__(self, key, value):
        self.fields[key] = value

    def parse_data(self, data):
        """
        Parses an ASN.1 data structure returned from the server based on the fields initialised in the child
        class. Will assert that the sizes are correct and that the values set are a valid DER encoded
        ASN.1 structure

        :param data: The raw ASN.1 data returned from the server
        """
        type_byte = struct.unpack('B', data[:1])[0]
        if type_byte != self.type:
            raise AsnStructureException("Expecting %s type to be (%x), was (%x)" % (self.name, self.type, type_byte))

        decoded_data, total_bytes = unpack_asn1(data)

        # Remove the bytes from the original type and length for comparison later
        total_bytes -= total_bytes - len(decoded_data)

        new_offset = 0
        for field in self.fields:
            offset = parse_context_field(decoded_data, self[field])
            new_offset += offset

        assert new_offset == total_bytes

    def get_data(self):
        """
        Creates an ASN.1 data structure based on the values already set in the object. Will throw an error in
        get_context_field is the value is not set and the field is mandatory.

        :return: An ASN.1 data structure to send to the server.
        """
        values = b''
        for field in self.fields:
            value = get_context_field(self[field])
            values += value

        data = struct.pack('B', self.type)
        data += pack_asn1(values)

        return data
