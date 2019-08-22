from c42 import rsa_pkcs1

# Bleichenbacher paper:
# http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf

# I decided to implement the whole thing right away instead of starting with a
# simpler version as the challenge states. So c48 will be pretty much the same
# as this challenge.

class padding_oracle(rsa_pkcs1):
    def padded(self, ct):
        pt = self.decrypt(ct, True)
        npad = self.k - len(pt)
        pt = npad * b'\x00' + pt
        return pt[:2] == b'\x00\x02'

def ceildiv(u, v):
    return (u + v - 1) // v

def step2a(s, e, n, c0, padded):
    ct = c0 * pow(s, e, n) % n
    while not padded(ct):
        s += 1
        ct = c0 * pow(s, e, n) % n
    return s

def step2b(s, e, n, c0, padded):
    s += 1
    ct = c0 * pow(s, e, n) % n
    while not padded(ct):
        s += 1
        ct = c0 * pow(s, e, n) % n
    return s

def step2c(s, e, n, c0, B, M, padded):
    a, b = M[0]
    r = ceildiv(2 * (b*s - 2*B), n)
    while True:
        lower = ceildiv(2*B + r*n, b)
        upper = (3*B + r*n) // a
        for si in range(lower, upper+1):
            ct = c0 * pow(si, e, n) % n
            if padded(ct):
                return si
        r += 1

def step3(s, n, B, M):
    Mn = []
    for a, b in M:
        lower = ceildiv(a*s - 3*B + 1, n)
        upper = (b*s - 2*B) // n
        for r in range(lower, upper+1):
            iv1 = max(a, ceildiv(2*B + r*n, s))
            iv2 = min(b, (3*B - 1 + r*n) // s)
            if (iv1, iv2) not in Mn:
                Mn += [(iv1, iv2)]
    return Mn

def step4(n, M):
    if len(M) == 1 and M[0][0] == M[0][1]:
        return M[0][0] % n

def bleichenbacher(c0, oracle, pub):
    e, n = pub
    k = (n.bit_length() + 7) // 8
    B = 2**(8*k - 16)
    M = [(2*B, 3*B-1)]
    s = ceildiv(n, 3*B)
    s = step2a(s, e, n, c0, oracle)
    M = step3(s, n, B, M)
    while not step4(n, M):
        if len(M) > 1:
            s = step2b(s, e, n, c0, oracle)
        else:
            s = step2c(s, e, n, c0, B, M, oracle)
        M = step3(s, n, B, M)
    return step4(n, M).to_bytes(k, 'big')

def main():
    p = padding_oracle(k=256)
    msg = b'kick it, CC'
    plaintext = p.pad_pkcs1(msg, btype=2)
    ciphertext = p.encrypt(plaintext)

    pt = bleichenbacher(c0=ciphertext, oracle=p.padded, pub=p.publickey())
    if pt == plaintext:
        print('Found plaintext!')
    else:
        print(pt)
