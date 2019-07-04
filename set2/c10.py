# openssl:
# openssl aes-128-cbc -d -a -in c10data -K 59454c4c4f57205355424d4152494e45 -iv 00000000000000000000000000000000
# python easy mode:
# AES.new('YELLOW SUBMARINE', AES.MODE_CBC, '\x00'*16).decrypt(data)
# python hard mode: see below 8-)

import numpy as np
from c09 import ecb_cipher, pad_pkcs7, unpad_pkcs7

class cbc_cipher(ecb_cipher):
    # Set iv to None to generate a random IV
    # Set iv to -1 to generate a random IV for every encryption call
    def __init__(self, key=None, iv=None):
        super().__init__(key)
        self.iv = iv if iv else np.random.bytes(self.bsz)

    def encrypt(self, data):
        data = pad_pkcs7(data, self.bsz)
        output = bytes()
        iv = self.iv
        for i in range(0, len(data), self.bsz):
            block = self.cph.encrypt(bytes([a^b for a,b in zip(data[i:i+self.bsz],iv)]))
            output += block
            iv = block
        return output

    def decrypt(self, data):
        output = bytes()
        iv = self.iv
        for i in range(0, len(data), self.bsz):
            block = self.cph.decrypt(data[i:i+self.bsz])
            output += bytes([a^b for a,b in zip(block,iv)])
            iv = data[i:i+self.bsz]
        return unpad_pkcs7(output)

    @staticmethod
    def encrypt_cbc(data, key=np.random.bytes(16), iv=np.random.bytes(16)):
        return cbc_cipher(key, iv).encrypt(data)

    @staticmethod
    def decrypt_cbc(data, key, iv):
        return cbc_cipher(key, iv).decrypt(data)

def main():
    from base64 import b64decode

    with open('set2/c10data') as f:
        data = b64decode(f.read())
    cph = cbc_cipher(b'YELLOW SUBMARINE', bytes(16))
    print(cph.decrypt(data))
