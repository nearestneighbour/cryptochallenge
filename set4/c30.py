from c28 import lrot, MAXINT

# Pseudocode:
# https://tools.ietf.org/html/rfc1320

class md4(sha1): # inherit auth(), hmac() from sha1
    def __init__(self):
        self.h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

    def digest(self, msg):
        msg = self.pad_msg(msg)
        h = [i for i in self.h] # h=self.h stopped working since c28
        def F(x, y, z): return (x & y) | (~x & z)
        def G(x, y, z): return (x & y) | (x & z) | (y & z)
        def H(x, y, z): return x ^ y ^ z
        u = [3, 7, 11, 19]
        v = [3, 5, 9, 13]
        w = [3, 9, 11, 15]
        m = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        n = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]

        for c in range(0, len(msg), 64):
            X = [int.from_bytes(msg[c:c+64][i:i+4], 'little') for i in range(0, 64, 4)]
            hh = [i for i in h] # hh = h does not work for some reason
            for i in range(16):
                tmp = h[-i%4] + F(h[(1-i)%4], h[(2-i)%4], h[(3-i)%4]) + X[i]
                h[-i%4] = lrot(tmp & MAXINT, u[i%4])
            for i in range(16):
                tmp = h[-i%4] + G(h[(1-i)%4], h[(2-i)%4], h[(3-i)%4]) + X[m[i]] + 0x5A827999
                h[-i%4] = lrot(tmp & MAXINT, v[i%4])
            for i in range(16):
                tmp = h[-i%4] + H(h[(1-i)%4], h[(2-i)%4], h[(3-i)%4]) + X[n[i]] + 0x6ED9EBA1
                h[-i%4] = lrot(tmp & MAXINT, w[i%4])

            h = [(i+j) & MAXINT for i,j in zip(h, hh)]

        return b''.join([i.to_bytes(4, 'little') for i in h])

    def pad_msg(self, msg):
        ml = (len(msg) * 8).to_bytes(8, 'little')
        msg += b'\x80'
        while len(msg) % 64 != 56:
            msg += b'\x00'
        return msg + ml

class md4_append_msg(md4):
    def __init__(self, state, prep_len):
        self.h = state
        self.pl = prep_len

    def pad_msg(self, msg): # Overwrite sha1's pad_msg function
        ml = ((len(msg) + self.pl) * 8).to_bytes(8, 'little')
        msg += bytes([128])
        while (len(msg) % 64) < 56:
            msg += b'\x00'
        return msg + ml

def main():
    import numpy as np
    key = np.random.bytes(16)
    org_msg = (b'comment1=cooking%20MCs;userdata=foo;'
               b'comment2=%20like%20a%20pound%20of%20bacon')
    org_mac = md4().auth(org_msg, key)
    prepend_len = len(md4().pad_msg(bytes(16) + org_msg))
    state = [int.from_bytes(org_mac[i:i+4], 'little') for i in range(0, 16, 4)]
    m = md4_append_msg(state, prepend_len)
    new_mac = m.digest(b';admin=true')
    print('Our MAC: ', new_mac)
    mac = md4().digest(md4().pad_msg(key+org_msg)+b';admin=true')
    print('Valid MAC: ', mac)
