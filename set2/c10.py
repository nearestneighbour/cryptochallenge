# openssl:
# openssl aes-128-cbc -d -a -in c10data -K 59454c4c4f57205355424d4152494e45 -iv 00000000000000000000000000000000
# python easy mode:
# AES.new('YELLOW SUBMARINE', AES.MODE_CBC, '\x00'*16).decrypt(data)

from base64 import b64decode
from Crypto.Cipher import AES

def decrypt_cbc(data, key, iv):
    cph = AES.new(key, AES.MODE_ECB)
    msg = bytes()
    for i in range(0, len(data), 16):
        block = cph.decrypt(data[i:i+16])
        msg += bytes([a^b for a,b in zip(block,iv)])
        iv = data[i:i+16]
    return msg

def encrypt_cbc(msg, key, iv):
    cph = AES.new(key, AES.MODE_ECB)
    data = bytes()
    for i in range(0, len(msg), 16):
        block = cph.encrypt(bytes([a^b for a,b in zip(msg[i:i+16],iv)]))
        data += block
        iv = block
    return data

with open('c10data') as f:
    data = b64decode(f.read())

key = bytes([ord(c) for c in 'YELLOW SUBMARINE'])
iv = bytes(16)
result = decrypt_cbc(data, key, iv)
