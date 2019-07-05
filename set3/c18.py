from Crypto.Cipher import AES
from Crypto.Util import Counter
import numpy as np

class ctr_cipher:
    def __init__(self, **kwargs):
        self.key = kwargs.pop('key', np.random.bytes(16))
        self.kwargs = kwargs # for counter object
        self.kwargs['prefix'] = self.kwargs.pop('prefix', bytes(8))

    def encrypt(self, data):
        ctr = Counter.new(64, **self.kwargs)
        cph = AES.new(self.key, AES.MODE_CTR, counter=ctr)
        return cph.encrypt(data)

    def decrypt(self, data):
        ctr = Counter.new(64, **self.kwargs)
        cph = AES.new(self.key, AES.MODE_CTR, counter=ctr)
        return cph.decrypt(data)

def main():
    from base64 import b64decode

    data = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    key = b'YELLOW SUBMARINE'
    cph = ctr_cipher(key=key, prefix=bytes(8), initial_value=0, little_endian=True)
    print(cph.decrypt(b64decode(data)))
