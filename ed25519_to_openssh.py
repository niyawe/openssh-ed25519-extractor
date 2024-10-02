#!/usr/bin/env python3

import base64
import secrets
import sys
from ed25519 import secret_to_public

keyformat = input("key format [hex, base64]: ")

if not keyformat in ['hex','base64']:
    print("unknown key format")
    sys.exit(1)

keybytes = bytes()

if keyformat == "hex":
    key = ""
    while len(key) < 64:
        key += input("key: ")
    if len(key) != 64:
        print("key too long")
        sys.exit(1)
    keybytes = bytes.fromhex(key)
elif keyformat == "base64":
    key = ""
    decoded_len = 0
    while decoded_len != 32:
        key += input("key: ")
        tmp_key = key + "=" * ((4 - len(key) % 4) % 4)
        decoded_len = len(base64.b64decode(tmp_key))
    key += "=" * ((4 - len(key) % 4) % 4)
    keybytes = base64.b64decode(tmp_key)
else:
    pass

pubkey = secret_to_public(keybytes)
print("pubkey: ", pubkey.hex())

# AUTH_MAGIC
data = b'openssh-key-v1\0'
# cipher name
data += b'\0\0\0\x04none'
# kdf name
data += b'\0\0\0\x04none'
# kdf options
data += b'\0\0\0\0'
# number of keys
data += b'\0\0\0\x01'
# public key
data += b'\0\0\0\x33'
data += b'\0\0\0\x0b'
data += b'ssh-ed25519'
# public key length
data += b'\0\0\0\x20'
# public key
data += pubkey
# private key length
data += b'\0\0\0\x88'
# checkint
checkint = secrets.token_bytes(4)
data += checkint
data += checkint
data += b'\0\0\0\x0b'
data += b'ssh-ed25519'
# public key length
data += b'\0\0\0\x20'
# public key
data += pubkey
# private key length
data += b'\0\0\0\x40'
data += keybytes
# comment length
data += b'\0\0\0\0'
# padding
data += b'\x01\x02\x03\x04\x05'
encoded_data = base64.b64encode(data)

print('-----BEGIN OPENSSH PRIVATE KEY-----')
for i in range(0, len(encoded_data), 70):
    print(encoded_data[i:i+70].decode("utf-8"))
print('-----END OPENSSH PRIVATE KEY-----')
