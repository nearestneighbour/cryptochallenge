from c28 import sha1, lrot, MAXINT

class md4(sha1): # Inherit digest and auth functions from sha1 class
    def __init__(self):
        self.h = [0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210]

    def digest(self, msg):
        msg = self.pad_msg(msg)
        def F(x, y, z): return (x & y) | (((1 << 32) - 1 - x) & z)
        def G(x, y, z): return (x & y) | (x & z) | (y & z)
        def H(x, y, z): return x ^ y ^ z
        h = self.h
        hh = self.h
        u = [3, 7, 11, 19]
        v = [3, 5, 9, 13]
        w = [3, 9, 11, 15]
        c = 0x5A827999
        d = 0x6ED9EBA1
        m = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        n = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        q = ['a','b','c','d']

        for c in range(0, len(msg), 64):
            X = [int.from_bytes(msg[c:c+64][i:i+4], 'big') for i in range(0, 64, 4)]
            for i in range(16):
                tmp = h[-i%4] + F(h[(1-i)%4],h[(2-i)%4],h[(3-i)%4]) + X[i]
                h[-i%4] = lrot(tmp & MAXINT, u[i%4])
            for i in range(16):
                tmp = h[-i%4] + G(h[(1-i)%4],h[(2-i)%4],h[(3-i)%4]) + X[m[i]] + c
                h[-i%4] = lrot(tmp & MAXINT, v[i%4])
            for i in range(16):
                tmp = h[-i%4] + H(h[(1-i)%4],h[(2-i)%4],h[(3-i)%4]) + X[n[i]] + d
                h[-i%4] = lrot(tmp & MAXINT, w[i%4])

            h = [(i+j) & MAXINT for i,j in zip(h, hh)]

        return b''.join([i.to_bytes(4, 'little') for i in h])
