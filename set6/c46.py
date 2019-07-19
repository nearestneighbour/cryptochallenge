from base64 import b64decode
from c39 import rsa

class parity_oracle(rsa):
    def is_even(self, ct): # True if even
        return self.decrypt(ct) % 2 == 0

# This binary search algo can never find the last byte, not sure why
def main():
    r = parity_oracle()
    ct = r.encrypt(b64decode('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGF'
        'yb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='))
    e, n = r.publickey()
    
    lb, ub = 0, n
    while lb <= ub:
        mid = (ub + lb) // 2
        ct *= pow(2, e, n)
        if r.is_even(ct):
            ub = mid - 1
        else:
            lb = mid + 1
        print(ub.to_bytes((ub.bit_length() + 7) // 8, 'big'))
