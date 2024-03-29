from Crypto.Util.number import getPrime
import random
from c28 import sha1
from c39 import invmod

def dsa_param_gen(L=15, N=10):
    q = getPrime(N)
    p = getPrime(L)
    while (p-1) % q != 0:
        p = getPrime(L)
    h = random.randint(2, p-2)
    g = pow(h, (p-1)//q, p)
    while g == 1:
        g = pow(h, (p-1)/q, p)
    return p, q, g

class dsa:
    # Generating big params takes way too long so I use these:
    p = int(
        '800000000000000089e1855218a0e7dac38136ffafa72eda7'
        '859f2171e25e65eac698c1702578b07dc2a1076da241c76c6'
        '2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe'
        'ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2'
        'b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87'
        '1a584471bb1', 16
    )
    q = int('f4f47f05794b256174bba6e9b396a7707e563c5b', 16)
    g = int(
        '5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119'
        '458fef538b8fa4046c8db53039db620c094c9fa077ef389b5'
        '322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047'
        '0f5b64c36b625a097f1651fe775323556fe00b3608c887892'
        '878480e99041be601a62166ca6894bdd41a7054ec89f756ba'
        '9fc95302291', 16
    )

    def __init__(self, p=None, q=None, g=None, hashfunc=sha1().intdigest):
        self.p = p if p else dsa.p
        self.q = q if q else dsa.q
        self.g = g if g else dsa.g
        self.H = hashfunc
        self.generate_keypair(True)

    def generate_keypair(self, applytoself=False):
        x = random.randint(1, self.q-1)
        y = pow(self.g, x, self.p)
        if applytoself:
            self.x = x
            self.y = y
        else:
            return x, y

    def sign(self, msg, x=None):
        x = x if x else self.x
        r = 0
        while r == 0:
            k = random.randint(1, self.q-1)
            r = pow(self.g, k, self.p) % self.q
        s = invmod(k, self.q) * (self.H(msg) + x*r) % self.q
        return r, s

    def verify(self, msg, sig, y=None):
        y = y if y else self.y
        r, s = sig
        assert r in range(1, self.q) and s in range(1, self.q), "Invalid signature"
        w = invmod(s, self.q)
        u1 = self.H(msg) * w % self.q
        u2 = r * w % self.q
        v = pow(self.g, u1, self.p) * pow(y, u2, self.p) % self.p % self.q
        return v == r

def priv_from_k(hashint, sig, k, q=dsa.q):
    r, s = sig
    return invmod(r, q) * (s * k - hashint) % q

def main():
    y = int('84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4'
        'abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004'
        'e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed'
        '1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b'
        'bb283e6633451e535c45513b2d33c99ea17', 16
    )
    msg = (b'For those that envy a MC it can be hazardous to your health\n'
        b'So be friendly, a matter of life and death, just like a etch-a-sketch\n')
    sig = (548099063082341131477253921760299949438196259240,
        857042759984254168557880549501802188789837994940)
    for k in range(2**16):
        x = priv_from_k(sha1().intdigest(msg), sig, k)
        yt = pow(dsa.g, x, dsa.p)
        if yt == y:
            break
    print('Value of k: ', k)
    x = hex(x)[2:].encode()
    print('Private key fingerprint: ', sha1().digest(x).hex())
