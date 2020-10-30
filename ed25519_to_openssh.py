#!/usr/bin/env python3

import base64
import ed25519
import secrets
import sys

keyformat = input("key format [hex, base64]: ")

if not keyformat in ['hex','base64']:
    print("unknown key format")
    sys.exit(1)

key = input("key: ")

key = ed25519.from_ascii(key, encoding=keyformat)
privkey = ed25519.SigningKey(key)
pubkey = privkey.get_verifying_key()

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
data += pubkey.to_bytes()
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
data += pubkey.to_bytes()
# private key length
data += b'\0\0\0\x40'
data += privkey.to_bytes()
# comment length
data += b'\0\0\0\0'
# padding
data += b'\x01\x02\x03\x04\x05'
encoded_data = base64.b64encode(data)

print('-----BEGIN OPENSSH PRIVATE KEY-----')
for i in range(0, len(encoded_data), 70):
    print(encoded_data[i:i+70].decode("utf-8"))
print('-----END OPENSSH PRIVATE KEY-----')
