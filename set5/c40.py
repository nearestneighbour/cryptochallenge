from c36_client import int2bytes
from c39 import rsa, invmod

# CRT stands for Chinese Remainer Theorem:
# https://en.wikipedia.org/wiki/Chinese_remainder_theorem

def cube_root(x): # Binary search
    l = 0; r = x // 3
    while l < r:
        m = (l + r) // 2
        if m**3 < x:
            l = m + 1
        else:
            r = m
    return l

def rsa_broadcast_attack(ct, n):
    res = 0
    for i in range(3):
        ms = n[(i+1)%3] * n[(i+2)%3]
        res += ct[i] * ms * invmod(ms, n[i])
    res %= n[0] * n[1] * n[2]
    return int2bytes(cube_root(res))

def main():
    msg = b'The quick brown fox jumps over the lazy dog'
    ct = []
    n = []
    for i in range(3):
        r = rsa()
        ct += [r.encrypt(msg)]
        n += [r.publickey()[1]]
    print('Msg decrypted using CRT: ', rsa_broadcast_attack(ct, n))
