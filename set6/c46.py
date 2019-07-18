from base64 import b64decode
from c39 import rsa

class oracle(rsa):
    def even_odd(self, ct): # True if even
        return self.decrypt(ct) % 2 == 0

def main():
    r = oracle()
    data = b64decode('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')
    ct = r.encrypt(data)
    # attack
