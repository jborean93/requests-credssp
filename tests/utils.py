import binascii

def byte_to_hex(byte_string):
    # Converts a byte string to a hex string for easy input and output of test data.
    return ' '.join([binascii.hexlify(x) for x in byte_string])

def hex_to_byte(hex_string):
    # Converts a hex string to byte string for comparison with expected byte string data
    hex_string = ''.join(hex_string.split(' '))
    return binascii.unhexlify(hex_string)