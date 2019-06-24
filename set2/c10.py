# openssl:
# openssl aes-128-cbc -d -a -in c10data -K 59454c4c4f57205355424d4152494e45 -iv 00000000000000000000000000000000
# python easy mode:
# AES.new('YELLOW SUBMARINE', AES.MODE_CBC, '\x00'*16).decrypt(data)
# python hard mode: see below 8-)

import numpy as np
from c09 import ecb_cipher, pad_pkcs7, unpad_pkcs7

class cbc_cipher(ecb_cipher):
    def encrypt(self, data, iv):
        data = pad_pkcs7(data, self.bsz)
        output = bytes()
        for i in range(0, len(data), self.bsz):
            block = self.cph.encrypt(bytes([a^b for a,b in zip(data[i:i+self.bsz],iv)]))
            output += block
            iv = block
        return output

    def decrypt(self, data, iv):
        output = bytes()
        for i in range(0, len(data), self.bsz):
            block = self.cph.decrypt(data[i:i+self.bsz])
            output += bytes([a^b for a,b in zip(block,iv)])
            iv = data[i:i+self.bsz]
        return unpad_pkcs7(output)

    @staticmethod
    def encrypt_cbc(data, key=np.random.bytes(16), iv=np.random.bytes(16)):
        return cbc_cipher(key).encrypt(data, iv)

def main():
    from base64 import b64decode

    with open('set2/c10data') as f:
        data = b64decode(f.read())
    cph = cbc_cipher(b'YELLOW SUBMARINE')
    print(cph.decrypt(data, bytes(16)))
