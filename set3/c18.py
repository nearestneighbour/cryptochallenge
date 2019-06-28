from Crypto.Cipher import AES
from Crypto.Util import Counter
import numpy as np

class ctr_cipher:
    def __init__(self, **kwargs):
        self.kwargs = kwargs # for reproducibility
        self.key = kwargs.pop('key',np.random.bytes(16))
        self.ctr = Counter.new(64, **kwargs)
        self.cph = AES.new(self.key, AES.MODE_CTR, counter=self.ctr)

    def encrypt(self, data):
        return self.cph.encrypt(data)

    def decrypt(self, data):
        return self.cph.decrypt(data)

    def copy(self):
        return ctr_cipher(**self.kwargs)

def main():
    from base64 import b64decode

    data = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    key = b'YELLOW SUBMARINE'
    cph = ctr_cipher(key=key, prefix=bytes(8), initial_value=0, little_endian=True)
    print(cph.decrypt(b64decode(data)))
