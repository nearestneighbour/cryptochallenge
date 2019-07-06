# Pseudocode from wikipedia:
# https://en.wikipedia.org/wiki/SHA-1#Examples_and_pseudocode

MAXINT = 2 ** 32 - 1

class sha1:
    def __init__(self):
        self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

    def digest(self, msg):
        msg = self.pad_msg(msg)
        h = self.h

        for c in range(0, len(msg), 64):
            w = [int.from_bytes(msg[c:c+64][i:i+4], 'big') for i in range(0, 64, 4)]
            for i in range(16,80):
                w += [lrot(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)]

            a, b, c, d, e = h

            for i in range(80):
                if i in range(20):
                    nb = (1 << 32) - 1 - b # not b
                    f = (b & c) | (nb & d)
                    k = 0x5A827999
                elif i in range(20, 40):
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif i in range(40, 60):
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                else:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6

                temp = lrot(a, 5) + f + e + k + w[i]
                e = d
                d = c
                c = lrot(b, 30)
                b = a
                a = temp & MAXINT

            h = [(i+j) & MAXINT for i,j in zip(h, (a, b, c, d, e))]

        return b''.join([i.to_bytes(4, 'big') for i in h])
        # This does the same as:
        #return (
        #    h[0]<<128 | h[1]<<96 | h[2]<<64 | h[3]<<32 | h[4]
        #).to_bytes(20, 'big')

    def pad_msg(self, msg):
        ml = (len(msg) * 8).to_bytes(8, 'big')
        msg += b'\x80' # append 1 bit
        while len(msg) % 64 != 56:
            msg += b'\x00'
        return msg + ml

    def auth(self, msg, key):
        return self.digest(key + msg)

def lrot(x, n):
    y = x << n
    y += y >> 32
    return y % 2**32
