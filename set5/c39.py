from Crypto.Util.number import getPrime
from c36_client import int2bytes

# Pseudocode from:
# https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Modular_integers
def invmod(a, m):
    t0, t1 = 0, 1
    r0, r1 = m, a
    while r1 != 0:
        q = r0 // r1
        t0, t1 = t1, t0 - q * t1
        r0, r1 = r1, r0 - q * r1
    return None if r0 > 1 else t0 % m

def genprime(e=3, k=1024):
    d = None
    while d == None:
        p = getPrime(k // 2)
        q = getPrime(k // 2)
        d = invmod(e, (p-1)*(q-1))
    return p, q

# Maximum message length depends on size of primes,
# ML=12 for n=50, ML=124 for n=500
class rsa:
    def __init__(self, p=None, q=None, e=3, k=1024):
        if not (p and q):
            p, q = genprime(e, k)
        self.n = p * q
        self.d = invmod(e, (p-1)*(q-1))
        self.e = e

    def encrypt(self, msg, tobytes=False):
        if type(msg) == bytes:
            msg = int.from_bytes(msg, 'big')
        msg = pow(msg, self.e, self.n)
        return int2bytes(msg) if tobytes else msg

    def decrypt(self, msg, tobytes=False):
        if type(msg) == bytes:
            msg = int.from_bytes(msg, 'big')
        msg = pow(msg, self.d, self.n)
        return int2bytes(msg) if tobytes else msg

    def publickey(self):
        return self.e, self.n

def main():
    r = rsa()
    msg = b'thisispatrick'
    print('Plaintext message: ', msg)
    msg = r.encrypt(msg, True)
    print('Encrypted message: ', msg)
    msg = r.decrypt(msg, True)
    print('Decrypted message: ', msg)
