from Crypto.Cipher import AES
import numpy as np

def pad_bytes(msg, bsz):
    if type(msg) == str:
        msg = bytes([ord(i) for i in msg])

    npad = bsz - (len(msg) % bsz)
    for i in range(npad):
        msg += bytes([npad])
    return msg

def unpad_bytes(msg):
    return msg[:-msg[-1]]

# New version of the functions from challenge 7, convenient for future challenges
class ecb_cipher:
    def __init__(self, key=None):
        self.key = key if key else np.random.bytes(16)
        self.bsz = len(self.key)
        self.cph = AES.new(self.key, AES.MODE_ECB)

    def encrypt(self, data):
        return self.cph.encrypt(pad_bytes(data, self.bsz))

    def decrypt(self, data):
        return unpad_bytes(self.cph.decrypt(data))

    @staticmethod
    def encrypt_ecb(data, key=np.random.bytes(16)):
        return ecb_cipher(key).encrypt(data)

def main():
    msg = b'YELLOW SUBMARINE'
    print(pad_bytes(msg, 20))
