"""
These values have been computed manually from a working CredSSP implementation.
Unfortunately Microsoft don't have examples in the MS-CSSP document which
details the protocol but this is the next best thing.
"""

domain = 'CORP'.encode('utf-16-le')
user = 'USERNAME123'.encode('utf-16-le')
password = 'FakePassword1234'.encode('utf-16-le')

# The negotiate token sent to the server first
negotiate_token = b'\x4E\x54\x4C\x4D\x53\x53\x50\x00' \
                  b'\x01\x00\x00\x00\x32\x90\x88\xE2' \
                  b'\x04\x00\x04\x00\x28\x00\x00\x00' \
                  b'\x00\x00\x00\x00\x2C\x00\x00\x00' \
                  b'\x06\x01\xB1\x1D\x00\x00\x00\x0F' \
                  b'\x43\x4F\x52\x50'

negotiate_nego_data = b'\x30\x30\xA0\x2E\x04\x2C' + negotiate_token

negotiate_ts_request = b'\x30\x3B\xA0\x03\x02\x01\x03\xA1' \
                       b'\x34\x30\x32' + \
                       negotiate_nego_data

# The challenge token received from the server
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

challenge_nego_data = b'\x30\x81\xF4\xA0\x81\xF1\x04\x81' \
                      b'\xEE' + \
                      challenge_token

challenge_ts_request = b'\x30\x82\x01\x02\xA0\x03\x02\x01' \
                       b'\x02\xA1\x81\xFA\x30\x81\xF7' + \
                       challenge_nego_data

# The authenticate token with the public key send to the server
pub_key_token = b'\x01\x00\x00\x00\xF9\x44\x30\x13' \
                b'\x86\x87\x72\xE8\x00\x00\x00\x00' \
                b'\xEF\x33\xA3\x34\x6B\x18\xEA\x02' \
                b'\x13\xB1\x0A\x2C\xD0\xC3\x01\x85' \
                b'\x28\x4C\x7C\xA6\xFA\x9F\xBD\xD5' \
                b'\x8F\x2E\x2D\x98\xA8\x19\xE2\xEB' \
                b'\x76\xD1\x5C\x23\x64\xBC\xE0\xEB' \
                b'\x6B\x82\x5E\x5D\xC3\xFF\x85\x01' \
                b'\x23\xDD\x1D\x83\xF1\x26\x02\x1E' \
                b'\x1E\x69\xCA\x8F\xB2\xB9\xD9\x23' \
                b'\xCD\x71\x64\x24\x93\xBB\x54\x67' \
                b'\x63\xA9\x03\x57\x3A\x13\x0A\x01' \
                b'\xE8\x48\x23\x57\x54\x43\x62\xE9' \
                b'\xE3\xAD\xFE\xE7\x75\x73\x9D\xDA' \
                b'\x15\x8C\xC0\x32\xE8\x3F\x20\xD9' \
                b'\xB3\xC3\xCB\xB2\xFE\x32\xC4\x6F' \
                b'\xA1\x63\x7B\x78\x14\xA3\xA0\x15' \
                b'\x6F\xD4\x89\x49\x05\x62\xDF\x7E' \
                b'\x18\xED\x11\xDF\x28\x5C\x95\x45' \
                b'\x0A\xF9\xEA\xB2'

auth_token = b'\x4E\x54\x4C\x4D\x53\x53\x50\x00' \
             b'\x03\x00\x00\x00\x18\x00\x18\x00' \
             b'\x67\x00\x00\x00\xFE\x00\xFE\x00' \
             b'\x7F\x00\x00\x00\x04\x00\x04\x00' \
             b'\x58\x00\x00\x00\x0B\x00\x0B\x00' \
             b'\x5C\x00\x00\x00\x00\x00\x00\x00' \
             b'\x67\x00\x00\x00\x10\x00\x10\x00' \
             b'\x7D\x01\x00\x00\x36\x82\x89\xE2' \
             b'\x06\x01\xB1\x1D\x00\x00\x00\x0F' \
             b'\xFD\xCB\xB8\x11\xD4\xE6\x6E\x2D' \
             b'\x58\x6B\x99\xA9\xBC\xAB\x2F\x0C' \
             b'\x43\x4F\x52\x50\x55\x53\x45\x52' \
             b'\x4E\x41\x4D\x45\x31\x32\x33\x00' \
             b'\x00\x00\x00\x00\x00\x00\x00\x00' \
             b'\x00\x00\x00\x00\x00\x00\x00\x00' \
             b'\x00\x00\x00\x00\x00\x00\x00\xAD' \
             b'\xE7\x28\x48\x97\xCB\xBE\xE5\xF7' \
             b'\xC3\xC7\xB3\xD4\xE9\x75\x47\x01' \
             b'\x01\x00\x00\x00\x00\x00\x00\xC5' \
             b'\xBE\x86\x1B\x94\x04\xD2\x01\x52' \
             b'\x00\xAD\x5B\xDB\x99\x84\x12\x00' \
             b'\x00\x00\x00\x02\x00\x08\x00\x43' \
             b'\x00\x4F\x00\x52\x00\x50\x00\x01' \
             b'\x00\x1A\x00\x43\x00\x4F\x00\x4D' \
             b'\x00\x50\x00\x55\x00\x54\x00\x45' \
             b'\x00\x52\x00\x48\x00\x4F\x00\x53' \
             b'\x00\x54\x00\x31\x00\x04\x00\x1E' \
             b'\x00\x63\x00\x6F\x00\x72\x00\x70' \
             b'\x00\x2E\x00\x6F\x00\x72\x00\x67' \
             b'\x00\x2E\x00\x63\x00\x6F\x00\x6D' \
             b'\x00\x2E\x00\x61\x00\x75\x00\x03' \
             b'\x00\x3A\x00\x43\x00\x4F\x00\x4D' \
             b'\x00\x50\x00\x55\x00\x54\x00\x45' \
             b'\x00\x52\x00\x48\x00\x4F\x00\x53' \
             b'\x00\x54\x00\x31\x00\x2E\x00\x63' \
             b'\x00\x6F\x00\x72\x00\x70\x00\x2E' \
             b'\x00\x6F\x00\x72\x00\x67\x00\x2E' \
             b'\x00\x63\x00\x6F\x00\x6D\x00\x2E' \
             b'\x00\x61\x00\x75\x00\x05\x00\x14' \
             b'\x00\x6F\x00\x72\x00\x67\x00\x2E' \
             b'\x00\x63\x00\x6F\x00\x6D\x00\x2E' \
             b'\x00\x61\x00\x75\x00\x07\x00\x08' \
             b'\x00\xC5\xBE\x86\x1B\x94\x04\xD2' \
             b'\x01\x06\x00\x04\x00\x02\x00\x00' \
             b'\x00\x0A\x00\x10\x00\xDB\x1E\x4B' \
             b'\x24\x9B\x21\x65\x64\x26\x61\xDB' \
             b'\x92\xE4\xB9\xF6\x4A\x00\x00\x00' \
             b'\x00\x00\x00\x00\x00\xC0\x63\x23' \
             b'\x32\xE6\x45\x7E\xE9\x7A\xF1\x4E' \
             b'\xC9\xED\xC9\x15\x85'

auth_nego_data = b'\x30\x82\x01\x95\xA0\x82\x01\x91' \
                 b'\x04\x82\x01\x8D' + \
                 auth_token

auth_ts_request = b'\x30\x82\x02\x48\xA0\x03\x02\x01' \
                  b'\x03\xA1\x82\x01\x9D\x30\x82\x01' \
                  b'\x99\x30\x82\x01\x95\xA0\x82\x01' \
                  b'\x91\x04\x82\x01\x8D' + \
                  auth_token + \
                  b'\xA3\x81\x9F\x04\x81\x9C' + \
                  pub_key_token

# The public key info received from the server
server_pub_key_token = b'\x01\x00\x00\x00\x3E\x79\xE3\x50' \
                       b'\xE7\xA1\x8D\xFC\x00\x00\x00\x00' \
                       b'\x2F\x93\x33\x21\x1D\xC6\xB6\x8D' \
                       b'\x73\x26\xEC\x38\x09\x81\x5E\xC9' \
                       b'\x62\x40\x6C\x59\x3E\xF1\xF5\xE1' \
                       b'\xED\x8E\x84\x8E\xB5\x0F\x8C\xF6' \
                       b'\xEF\x11\xFE\xD1\x43\xFC\x61\x37' \
                       b'\xFF\x08\xB5\x0E\x8B\xBC\x30\x23' \
                       b'\xA9\x46\xCE\x6B\x1A\xB6\x64\xBD' \
                       b'\x66\x26\x64\x27\x93\x19\x12\xD8' \
                       b'\xEC\xD7\x14\x67\x2F\x09\xCE\xC2' \
                       b'\xA0\xEF\x06\x87\xCF\xA6\x25\x45' \
                       b'\x06\xF0\x57\x90\xE1\xE3\xE6\x3F' \
                       b'\x71\x42\xD4\x30\x8A\x3D\x8A\x2B' \
                       b'\xC4\xBD\x72\x3E\x5F\x35\x52\xA6' \
                       b'\xA2\x9F\x09\xBA\xDF\x43\x34\xDF' \
                       b'\x46\x24\x1E\xBC\x20\x57\xBE\x8A' \
                       b'\xBF\x44\xA8\x70\xAB\xEE\xCE\xDD' \
                       b'\x49\xAC\xFE\x7A\x0D\x62\x41\x2A' \
                       b'\xA4\x90\x13\xD2'

public_key_ts_request = b'\x30\x81\xA7\xA0\x03\x02\x01\x02' \
                        b'\xA3\x81\x9F\x04\x81\x9C' + \
                        server_pub_key_token

# The credentials sent to the server
# need to use static encrypted credentials as we don't have a NTLM context to
# encrypt the values with
credentials_encrypted_password_creds = b'\x01\x00\x00\x00\x06\x34\x46\x86' \
                                       b'\xA6\x92\x0D\x3A\x01\x00\x00\x00' \
                                       b'\x19\x9F\xB6\x28\xEE\x15\xEC\x90' \
                                       b'\x76\x17\xBE\xD2\xC2\xD8\x7A\x2D' \
                                       b'\xC1\x36\x05\x71\x71\xCC\x91\xA2' \
                                       b'\xD7\x7B\x52\x22\x45\xEC\xFF\xEE' \
                                       b'\x70\x4D\x75\x69\x20\xBF\x51\xA6' \
                                       b'\xE1\x79\x6C\xB4\xAC\xF9\xB8\x05' \
                                       b'\x6C\x8B\x87\x1F\x19\x8F\xF0\x80' \
                                       b'\xB3\x34\x27\x40\x3D\xF2\x6E\xDD' \
                                       b'\x4E\xD3\x22\xBA\x48\x58\x08\x15' \
                                       b'\x2C\x8D\x02\xE9\xCD\xF0\xD1\x08' \
                                       b'\xEC\x79\x1B\xB0\x71\xF1\xD2'

credential_ts_password_creds = b'\x30\x4A\xA0\x0A\x04\x08\x43\x00' \
                               b'\x4F\x00\x52\x00\x50\x00\xA1\x18' \
                               b'\x04\x16\x55\x00\x53\x00\x45\x00' \
                               b'\x52\x00\x4E\x00\x41\x00\x4D\x00' \
                               b'\x45\x00\x31\x00\x32\x00\x33\x00' \
                               b'\xA2\x22\x04\x20\x46\x00\x61\x00' \
                               b'\x6B\x00\x65\x00\x50\x00\x61\x00' \
                               b'\x73\x00\x73\x00\x77\x00\x6F\x00' \
                               b'\x72\x00\x64\x00\x31\x00\x32\x00' \
                               b'\x33\x00\x34\x00'

credential_ts_credentials = b'\x30\x55\xA0\x03\x02\x01\x01\xA1' \
                            b'\x4E\x04\x4C' + \
                            credential_ts_password_creds

credential_ts_request = b'\x30\x70\xA0\x03\x02\x01\x03\xA2' \
                        b'\x69\x04\x67' + \
                        credentials_encrypted_password_creds
