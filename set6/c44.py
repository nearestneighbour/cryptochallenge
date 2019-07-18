from c28 import sha1
from c39 import invmod
from c43 import dsa, priv_from_k

def priv_from_sig_pair(m1, sig1, m2, sig2, q=dsa.q):
    r1, s1, r2, s2 = sig1 + sig2
    k = invmod((s1 - s2) % q, q) * ((m1 - m2) % q) % q
    x = priv_from_k(m1, sig1, k, q)
    # Return x=None if sigs were not generated with same k
    return k, x if x == priv_from_k(m2, sig2, k, q) else None

def main():
    with open('set6/c44data') as f:
        data = f.readlines()
        # Append ' ' to messages to get hash right
        msg = [(d[5:-1] + ' ').encode() for d in data[::4]]
        s = [int(d[3:-1]) for d in data[1::4]]
        r = [int(d[3:-1]) for d in data[2::4]]
        sig = [(i,j) for i,j in zip(r,s)]
        m = [d[3:-1] for d in data[3::4]]
        # Verify that messages are read correctly
        for i in range(len(msg)):
            if len(m[i]) == 39: # Some hashes have left out leading zeros
                m[i] = '0' + m[i]
            assert sha1().digest(msg[i]).hex() == m[i], "Could not read data correctly"
            m[i] = int(m[i], 16)

    for i in range(len(m)):
        for j in range(i):
            k, x = priv_from_sig_pair(m[i], sig[i], m[j], sig[j])
            if x: break

    xh = sha1().digest(hex(x)[2:].encode()).hex()
    print('Messages %d and %d were signed using repeated nonce.' % (j, i))
    print('Nonce: ', k)
    print('Private key: ', x)
    print('Private key fingerprint: ', xh)
