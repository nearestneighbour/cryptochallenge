import numpy as np
from c10 import cbc_cipher
from c15 import unpad_pkcs7

class random_cipher(cbc_cipher):
    def __init__(self, iv=None):
        super().__init__(iv=iv)
        with open('set3/c17data') as f:
            self.strings = f.read().split('\n')[:-1]

    def encrypt_string(self):
        string = self.strings[np.random.randint(len(self.strings))]
        return self.encrypt(string)

    def decrypt_string(self, data):
        string = self.decrypt(data)
        return string != None

# With help from: https://thmsdnnr.com/tutorials/javascript/cryptopals/2017/10/02/cryptopals-set3-challenge-17-cbc-padding-oracle.html
def decode_block_cbc(block, prev):
    guess = [0 for i in range(16)]
    for i in range(16):
        b = [guess[15-k]^(i+1) for k in range(i-1,-1,-1)]
        for j in range(256):
            guess[15-i] = j^prev[15-i]
            synth = (15-i) * b'X' + bytes([guess[15-i]^(i+1)]) + bytes(b)
            if cph.decrypt_string(synth + block):
                break
    return bytes([guess[i]^prev[i] for i in range(16)])

iv = np.random.bytes(16)
cph = random_cipher(iv=iv)

def main():
    ct = cph.encrypt_string()
    # Decode output block by block
    blocks = [decode_block_cbc(ct[:16], iv)]
    for i in range(len(ct) // 16 - 1):
        blocks += [decode_block_cbc(ct[i*16+16:i*16+32], ct[i*16:i*16+16])]
    pt = unpad_pkcs7(b''.join(blocks))
    print(pt)
