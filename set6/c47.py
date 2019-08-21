from c42 import rsa_pkcs1

# Bleichenbacher paper:
# http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf

class padding_oracle(rsa_pkcs1):
    def padded(self, ct):
        return self.decrypt(ct, True)[:2] == b'\x00\x02'

k = 256
B = 2**(k - 16)
p = padding_oracle(k=k)
e, n = p.e, p.n

m = p.pad_pkcs1(b'kick it, CC', blocktype=2)
#m = b'\x00\x02\x00\x01'
c = p.encrypt(m)

def ceildiv(u, v):
    return (u + v - 1) // v

def step2a():
    s1 = ceildiv(n, 3*B)
    ct = c * pow(s1, e, n) % n
    while not p.padded(ct):
        s1 += 1
        ct = c * pow(s1, e, n) % n
    return s1

def step2b(s):
    s += 1
    ct = c * pow(s, e, n) % n
    while not p.padded(ct):
        s += 1
        ct = c * pow(s, e, n) % n
    return s

def step2c(s, M):
    print('step2c')
    a, b = M[0]
    r = ceildiv(2 * (b*s - 2*B), n)
    while True:
        lower = ceildiv(2*B + r*n, b)
        upper = (3*B + r*n) // a
        for si in range(lower, upper+1):
            ct = c * pow(si, e, n) % n
            if p.padded(ct):
                return si
        r += 1

def step3(s, M):
    Mn = []
    for a, b in M:
        lower = (a*s - 3*B + 1) // n # floor
        upper = ceildiv(b*s - 2*B, n)
        for r in range(lower, upper+1):
            iv1 = max(a, ceildiv(2*B + r*n, s))
            iv2 = min(b, (3*B - 1 + r*n) // s)
            if (iv1, iv2) not in Mn:
                Mn += [(iv1, iv2)]
    return Mn

def step4(M):
    if len(M) == 1 and M[0][0] == M[0][1]:
        return M[0][0] % n

def attack():
    M = [(2*B, 3*B-1)]
    s = step2a()
    M = step3(s, M)
    while not step4(M):
        if len(M) > 1:
            s = step2b(s)
        else:
            s = step2c(s, M)
            print('2c')
        M = step3(s, M)
        print(s, len(M))
    return step4(M)
