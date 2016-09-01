import tests.utils as utils

"""
These values have been computed manually from a working CredSSP implementation. Unfortunately Microsoft
don't have examples in the MS-CSSP document which details the protocol but this is the next best thing.

You can use a program like ASN.1 Editor to view the binary file of these hex strings in an easy to view format.
https://www.sysadmins.lv/blog-en/asn1-editor-wpf-edition.aspx
"""

domain = 'CORP'.encode('utf-16le')
user = 'USERNAME123'.encode('utf-16le')
password = 'FakePassword1234'.encode('utf-16le')

# The negotiate token sent to the server first
negotiate_token = utils.hex_to_byte('4E 54 4C 4D 53 53 50 00 01 00 00 00 32 90 88 E2'
                                    '04 00 04 00 28 00 00 00 00 00 00 00 2C 00 00 00'
                                    '06 01 B1 1D 00 00 00 0F 43 4F 52 50')

negotiate_nego_data = utils.hex_to_byte('30 30 A0 2E 04 2C') + negotiate_token

negotiate_ts_request = utils.hex_to_byte('30 3B A0 03 02 01 03 A1 34 30 32') + negotiate_nego_data

# The challenge token received from the server
challenge_token = utils.hex_to_byte('4E 54 4C 4D 53 53 50 00 02 00 00 00 04 00 04 00'
                                    '38 00 00 00 36 82 89 E2 45 80 F2 D5 B4 F3 ED 50'
                                    '00 00 00 00 00 00 00 00 B2 00 B2 00 3C 00 00 00'
                                    '06 01 B1 1D 00 00 00 0F 43 4F 52 50 02 00 08 00'
                                    '43 00 4F 00 52 00 50 00 01 00 1A 00 43 00 4F 00'
                                    '4D 00 50 00 55 00 54 00 45 00 52 00 48 00 4F 00'
                                    '53 00 54 00 31 00 04 00 1E 00 63 00 6F 00 72 00'
                                    '70 00 2E 00 6F 00 72 00 67 00 2E 00 63 00 6F 00'
                                    '6D 00 2E 00 61 00 75 00 03 00 3A 00 43 00 4F 00'
                                    '4D 00 50 00 55 00 54 00 45 00 52 00 48 00 4F 00'
                                    '53 00 54 00 31 00 2E 00 63 00 6F 00 72 00 70 00'
                                    '2E 00 6F 00 72 00 67 00 2E 00 63 00 6F 00 6D 00'
                                    '2E 00 61 00 75 00 05 00 14 00 6F 00 72 00 67 00'
                                    '2E 00 63 00 6F 00 6D 00 2E 00 61 00 75 00 07 00'
                                    '08 00 C5 BE 86 1B 94 04 D2 01 00 00 00 00')

challenge_nego_data = utils.hex_to_byte('30 81 F4 A0 81 F1 04 81 EE') + challenge_token

challenge_ts_request = utils.hex_to_byte('30 82 01 02 A0 03 02 01 02 A1 81 FA 30 81 F7') + challenge_nego_data

# The authenticate token with the public key send to the server
pub_key_token = utils.hex_to_byte('01 00 00 00 F9 44 30 13 86 87 72 E8 00 00 00 00'
                                  'EF 33 A3 34 6B 18 EA 02 13 B1 0A 2C D0 C3 01 85'
                                  '28 4C 7C A6 FA 9F BD D5 8F 2E 2D 98 A8 19 E2 EB'
                                  '76 D1 5C 23 64 BC E0 EB 6B 82 5E 5D C3 FF 85 01'
                                  '23 DD 1D 83 F1 26 02 1E 1E 69 CA 8F B2 B9 D9 23'
                                  'CD 71 64 24 93 BB 54 67 63 A9 03 57 3A 13 0A 01'
                                  'E8 48 23 57 54 43 62 E9 E3 AD FE E7 75 73 9D DA'
                                  '15 8C C0 32 E8 3F 20 D9 B3 C3 CB B2 FE 32 C4 6F'
                                  'A1 63 7B 78 14 A3 A0 15 6F D4 89 49 05 62 DF 7E'
                                  '18 ED 11 DF 28 5C 95 45 0A F9 EA B2')

auth_token = utils.hex_to_byte('4E 54 4C 4D 53 53 50 00 03 00 00 00 18 00 18 00'
                               '67 00 00 00 FE 00 FE 00 7F 00 00 00 04 00 04 00'
                               '58 00 00 00 0B 00 0B 00 5C 00 00 00 00 00 00 00'
                               '67 00 00 00 10 00 10 00 7D 01 00 00 36 82 89 E2'
                               '06 01 B1 1D 00 00 00 0F FD CB B8 11 D4 E6 6E 2D'
                               '58 6B 99 A9 BC AB 2F 0C 43 4F 52 50 55 53 45 52'
                               '4E 41 4D 45 31 32 33 00 00 00 00 00 00 00 00 00'
                               '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 AD'
                               'E7 28 48 97 CB BE E5 F7 C3 C7 B3 D4 E9 75 47 01'
                               '01 00 00 00 00 00 00 C5 BE 86 1B 94 04 D2 01 52'
                               '00 AD 5B DB 99 84 12 00 00 00 00 02 00 08 00 43'
                               '00 4F 00 52 00 50 00 01 00 1A 00 43 00 4F 00 4D'
                               '00 50 00 55 00 54 00 45 00 52 00 48 00 4F 00 53'
                               '00 54 00 31 00 04 00 1E 00 63 00 6F 00 72 00 70'
                               '00 2E 00 6F 00 72 00 67 00 2E 00 63 00 6F 00 6D'
                               '00 2E 00 61 00 75 00 03 00 3A 00 43 00 4F 00 4D'
                               '00 50 00 55 00 54 00 45 00 52 00 48 00 4F 00 53'
                               '00 54 00 31 00 2E 00 63 00 6F 00 72 00 70 00 2E'
                               '00 6F 00 72 00 67 00 2E 00 63 00 6F 00 6D 00 2E'
                               '00 61 00 75 00 05 00 14 00 6F 00 72 00 67 00 2E'
                               '00 63 00 6F 00 6D 00 2E 00 61 00 75 00 07 00 08'
                               '00 C5 BE 86 1B 94 04 D2 01 06 00 04 00 02 00 00'
                               '00 0A 00 10 00 DB 1E 4B 24 9B 21 65 64 26 61 DB'
                               '92 E4 B9 F6 4A 00 00 00 00 00 00 00 00 C0 63 23'
                               '32 E6 45 7E E9 7A F1 4E C9 ED C9 15 85')

auth_nego_data = utils.hex_to_byte('30 82 01 95 A0 82 01 91 04 82 01 8D') + auth_token

auth_ts_request = utils.hex_to_byte('30 82 02 48 A0 03 02 01 03 A1 82 01 9D 30 82 01'
                                    '99 30 82 01 95 A0 82 01 91 04 82 01 8D') + auth_token + \
                  utils.hex_to_byte('A3 81 9F 04 81 9C') + pub_key_token

# The public key info received from the server
server_pub_key_token = utils.hex_to_byte('01 00 00 00 3E 79 E3 50 E7 A1 8D FC 00 00 00 00'
                                         '2F 93 33 21 1D C6 B6 8D 73 26 EC 38 09 81 5E C9'
                                         '62 40 6C 59 3E F1 F5 E1 ED 8E 84 8E B5 0F 8C F6'
                                         'EF 11 FE D1 43 FC 61 37 FF 08 B5 0E 8B BC 30 23'
                                         'A9 46 CE 6B 1A B6 64 BD 66 26 64 27 93 19 12 D8'
                                         'EC D7 14 67 2F 09 CE C2 A0 EF 06 87 CF A6 25 45'
                                         '06 F0 57 90 E1 E3 E6 3F 71 42 D4 30 8A 3D 8A 2B'
                                         'C4 BD 72 3E 5F 35 52 A6 A2 9F 09 BA DF 43 34 DF'
                                         '46 24 1E BC 20 57 BE 8A BF 44 A8 70 AB EE CE DD'
                                         '49 AC FE 7A 0D 62 41 2A A4 90 13 D2')

public_key_ts_request = utils.hex_to_byte('30 81 A7 A0 03 02 01 02 A3 81 9F 04 81 9C') + server_pub_key_token

# The credentials sent to the server
# need to use static encrypted credentials as we don't have a NTLM context to encrypt the values with
credentials_encrypted_password_creds = utils.hex_to_byte('01 00 00 00 06 34 46 86 A6 92 0D 3A 01 00 00 00'
                                                         '19 9F B6 28 EE 15 EC 90 76 17 BE D2 C2 D8 7A 2D'
                                                         'C1 36 05 71 71 CC 91 A2 D7 7B 52 22 45 EC FF EE'
                                                         '70 4D 75 69 20 BF 51 A6 E1 79 6C B4 AC F9 B8 05'
                                                         '6C 8B 87 1F 19 8F F0 80 B3 34 27 40 3D F2 6E DD'
                                                         '4E D3 22 BA 48 58 08 15 2C 8D 02 E9 CD F0 D1 08'
                                                         'EC 79 1B B0 71 F1 D2')

credential_ts_password_creds = utils.hex_to_byte('30 4A A0 0A 04 08 43 00 4F 00 52 00 50 00 A1 18'
                                                 '04 16 55 00 53 00 45 00 52 00 4E 00 41 00 4D 00'
                                                 '45 00 31 00 32 00 33 00 A2 22 04 20 46 00 61 00'
                                                 '6B 00 65 00 50 00 61 00 73 00 73 00 77 00 6F 00'
                                                 '72 00 64 00 31 00 32 00 33 00 34 00')

credential_ts_credentials = utils.hex_to_byte('30 55 A0 03 02 01 01 A1 4E 04 4C') + credential_ts_password_creds

credential_ts_request = utils.hex_to_byte('30 70 A0 03 02 01 03 A2 69 04 67') + credentials_encrypted_password_creds