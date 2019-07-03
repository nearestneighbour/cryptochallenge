import numpy as np

from c21 import mt19973_rng

class mt19973_stream(mt19973_rng):
    def __init__(self, seed=None):
        self.seed = seed if seed else np.random.randint(1 << 16)
        self.key = b''
        super().__init__(self.seed)

    def encrypt(self, data):
        if type(data) == str:
            data = bytes([ord(c) for c in data])
        while len(self.key) < len(data):
            self.key += self.rand().to_bytes(4, 'big')
        out = bytes([a^b for a,b in zip(data,self.key)])
        self.key = self.key[len(data):]
        return out

def main():
    cph = mt19973_stream()
    plain = np.random.bytes(50) + 14 * b'A'
    ct = cph.encrypt(plain)

    # Use brute force to check all 2**16 possible seeds...
    for i in range(1 << 16):
        cph1 = mt19973_stream(i)
        if cph1.encrypt(ct).endswith(14 * b'A'):
            break

    print('Found seed: ', i)
    print('Cipher seed: ', cph.seed)
