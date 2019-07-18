import random

class diffiehellman:
    def __init__(self, p, g, priv=None):
        self.p = p
        self.g = g
        self.priv = priv if priv else random.getrandbits(numbytes(p)*8) % p

    def publickey(self, tobytes=True):
        pk = pow(self.g, self.priv, self.p)
        if tobytes:
            pk = pk.to_bytes(numbytes(pk), 'big')
        return pk

    def secret(self, pubkey, tobytes=True):
        s = pow(pubkey, self.priv, self.p)
        if tobytes:
            s = s.to_bytes(numbytes(s), 'big')
        return s

def numbytes(s):
    n = 0
    while s > 0:
        s >>= 8
        n += 1
    return max(1, n)

N = int(
    'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
    'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
    '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
    '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
    '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
    'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
    'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
    'fffffffffffff', 16
)

def main():
    g = 2
    A = diffiehellman(N, g)
    B = diffiehellman(N, g)
    print(A.secret(B.publickey(False), False))
    print(B.secret(A.publickey(False), False))
