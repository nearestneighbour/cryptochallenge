# This can be done with openssl using the command:
# openssl aes-128-ecb -d -a -in s1c7data -K 59454c4c4f57205355424d4152494e45
# where 59454c4c4f57205355424d4152494e45 is the hex-encoded key YELLOW SUBMARINE

from Crypto.Cipher import AES

def decrypt_ecb(data, key):
    cph = AES.new(key, AES.MODE_ECB)
    return cph.decrypt(data)

def encrypt_ecb(data, key):
    cph = AES.new(key, AES.MODE_ECB)
    return cph.encrypt(data)

def main():
    from base64 import b64decode
    with open('set1/c07data') as f:
        data = b64decode(f.read())
    key = b'YELLOW SUBMARINE'
    print(decrypt_ecb(data, key))
