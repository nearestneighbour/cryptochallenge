def leftrotate(x, n):
    y = x << n
    y += y >> 32
    return y % 2**32

def sha1(msg):
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    ml = len(msg) * 8

    msg += bytes([128]) # append 1
    while (len(msg) % 64) < 56:
        msg += b'\x00'

    msg += ml.to_bytes(8, 'big')

    for c in range(0, len(msg), 64):
        chunk = msg[c:c+64]
        w = [int.from_bytes(chunk[i:i+4], 'big') for i in range(0, 64, 4)]
        for i in range(16,80):
            w += [leftrotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)]
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
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
            temp = leftrotate(a,5) + f + e + k + w[i]
            e = d
            d = c
            c = leftrotate(b, 30)
            b = a
            a = temp
        h0 += a
        h1 += b
        h2 += c
        h3 += d
        h4 += e

    return (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
