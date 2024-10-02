#!/usr/bin/env python3

import base64
import sys

if len(sys.argv) < 2:
    print("usage: ", sys.argv[0], " <id_ed25519>")
    sys.exit(1)

f = open(sys.argv[1], 'rb')
started = False
data = b''

for line in f.readlines():
    if line == b'-----BEGIN OPENSSH PRIVATE KEY-----\n':
        started = True
        continue
    if started and line == b'-----END OPENSSH PRIVATE KEY-----\n':
        break
    if started:
        data += line[:-1]
        continue
f.close()

data = base64.b64decode(data)

if data[:15] != b'openssh-key-v1\0':
    print("not a ssh-key")
    sys.exit(1)
data = data[15:]
cipher_name_len = int.from_bytes(bytes=data[:4], byteorder="big", signed=False)
data = data[4:]
cipher_name = data[:cipher_name_len]
data = data[cipher_name_len:]

if cipher_name != b'none':
    print("cannot handle encrypted keys at the moment")
    sys.exit(1)

kdf_name_len = int.from_bytes(bytes=data[:4], byteorder="big", signed=False)
data = data[4:]
kdf_name = data[:kdf_name_len]
data = data[kdf_name_len:]

if kdf_name != b'none':
    print("cannot handle encrypted keys at the moment")
    sys.exit(1)

kdf_options_len = int.from_bytes(bytes=data[:4], byteorder="big", signed=False)
data = data[4:]
kdf_options = data[:kdf_options_len]
data = data[kdf_options_len:]

if kdf_options_len > 0:
    print("cannot handle encrypted keys at the moment")
    sys.exit(1)


number_of_keys = int.from_bytes(bytes=data[:4], byteorder="big", signed=False)
data = data[4:]

if number_of_keys > 1:
    print("cannot handle more than one key at the moment")
    sys.exit(1)

public_key_len = int.from_bytes(bytes=data[:4], byteorder="big", signed=False)
data = data[4:]

public_key = data[:public_key_len]
data = data[public_key_len:]

public_key_type_len = int.from_bytes(bytes=public_key[:4], byteorder="big", signed=False)
public_key = public_key[4:]
public_key_type = public_key[:public_key_type_len]
public_key = public_key[public_key_type_len:]

if public_key_type != b'ssh-ed25519':
    print("this tool is only for ed25519 keys")
    sys.exit(1)

public_key_len = int.from_bytes(bytes=public_key[:4], byteorder="big", signed=False)
public_key = public_key[4:]
public_key = public_key[:public_key_len]

if public_key_len != 32:
    print("invalid public key length")
    sys.exit(1)

private_key_list_len = int.from_bytes(bytes=data[:4], byteorder="big", signed=False)
data = data[4:]
private_key_list = data[:private_key_list_len]
data = data[private_key_list_len:]

if private_key_list[:4] != private_key_list[4:8]:
    print("checkints do not match")
    sys.exit(1)
private_key_list = private_key_list[8:]

private_key_type_len = int.from_bytes(bytes=private_key_list[:4], byteorder="big", signed=False)
private_key_list = private_key_list[4:]
private_key_type = private_key_list[:private_key_type_len]
private_key_list = private_key_list[private_key_type_len:]

if private_key_type != b'ssh-ed25519':
    print("this tool is only for ed25519 keys")
    sys.exit(1)

second_public_key_len = int.from_bytes(bytes=private_key_list[:4], byteorder="big", signed=False)
private_key_list = private_key_list[4:]
second_public_key = private_key_list[:second_public_key_len]
private_key_list = private_key_list[second_public_key_len:]

if public_key != second_public_key:
    print("public key and public key in private part do not match")
    sys.exit(1)

private_key_len = int.from_bytes(bytes=private_key_list[:4], byteorder="big", signed=False)
private_key_list = private_key_list[4:]
private_key = private_key_list[:private_key_len]
private_key_list = private_key_list[private_key_len:]

seed = private_key[:32]
pubkey = private_key[32:]

print(seed[0:8].hex())
print(seed[8:16].hex())
print(seed[16:24].hex())
print(seed[24:32].hex())
print("base64 key:", base64.b64encode(seed).decode('utf-8'))

print("pubkey: ", pubkey.hex())
