from c10 import cbc_cipher

class cipher(cbc_cipher):
    def __init__(self):
        super().__init__()
        self.iv = self.key

    def decrypt(self, data):
        pt = super().decrypt(data, unpad=False)
        if max(pt) >= 128: # non ASCII compliant
            return pt

def main():
    import numpy as np
    cph = cipher()

    block = np.random.bytes(16)
    while cph.decrypt(block + bytes(16) + block) == None:
        block = np.random.bytes(16)

    pt = cph.decrypt(block + bytes(16) + block)
    c3_intermediate = pt[-16:]
    c1_intermediate = c3_intermediate
    print('Found key: ', bytes([a^b for a,b in zip(c1_intermediate, pt[:16])]))
    print('Actual key: ', cph.key)
