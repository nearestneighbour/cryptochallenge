from Crypto.Util import number
from c36_client import int2bytes

# Bugs:
# Maximum message length depends on size of primes, ML=12 for 50-bit primes,
# ML=124 for 500-bit primes

# egcd() and invmod() copied from:
# https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def invmod(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        return None # No solution exists
    else:
        return x % m

def genprime(e=3, n=1024):
    d = None
    while d == None:
        p = number.getPrime(n)
        q = number.getPrime(n)
        d = invmod(e, (p-1)*(q-1))
    return p, q

class rsa:
    def __init__(self, p=None, q=None, e=3, n=1024):
        if not (p and q):
            p, q = genprime(e, n)
        self.n = p * q
        self.d = invmod(e, (p-1)*(q-1))
        self.e = e

    def encrypt(self, msg, tobytes=True):
        msg = int.from_bytes(msg, 'big')
        msg = pow(msg, self.e, self.n)
        return int2bytes(msg) if tobytes else msg

    def decrypt(self, msg, tobytes=True):
        msg = int.from_bytes(msg, 'big')
        msg = pow(msg, self.d, self.n)
        return int2bytes(msg) if tobytes else msg

def main():
    r = rsa()
    msg = b'thisispatrick'
    print('Plaintext message: ', msg)
    msg = r.encrypt(msg)
    print('Encrypted message: ', msg)
    msg = r.decrypt(msg)
    print('Decrypted message: ', msg)
