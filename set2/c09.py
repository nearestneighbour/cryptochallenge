from Crypto.Cipher import AES
import numpy as np

def pad_pkcs7(data, bsz):
    if type(data) == str:
        data = data.encode()

    npad = (bsz - (len(data) % bsz)) % bsz
    for i in range(npad):
        data += bytes([npad])
    return data

def unpad_pkcs7(data):
    npad = data[-1]
    for i in data[-npad:]:
        if i != npad:
            return None
    return data[:-npad]

# New version of the functions from challenge 7, convenient for future challenges
class ecb_cipher:
    def __init__(self, key=None):
        self.key = key if key else np.random.bytes(16)
        self.bsz = len(self.key)
        self.cph = AES.new(self.key, AES.MODE_ECB)

    def encrypt(self, data):
        return self.cph.encrypt(pad_pkcs7(data, self.bsz))

    def decrypt(self, data):
        return unpad_pkcs7(self.cph.decrypt(data))

    @staticmethod
    def encrypt_ecb(data, key=np.random.bytes(16)):
        return ecb_cipher(key).encrypt(data)

def main():
    msg = b'YELLOW SUBMARINE'
    print(pad_pkcs7(msg, 20))
