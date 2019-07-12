from Crypto.Util import number
from c36_client import int2bytes

# Copied from https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def invmod(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

class rsa:
    def __init__(self, p=None, q=None, e=None):
        p = p if p else number.getPrime(50)
        q = q if q else number.getPrime(50)
        self.n = p * q
        self.e = e if e else 3
        print(p, q, self.e)
        self.d = invmod(e, (p-1)*(q-1))

    def encrypt_msg(self, msg):
        msg = int.from_bytes(msg, 'big')
        msg = pow(msg, self.e, self.n)
        return int2bytes(msg)

    def decrypt_msg(self, msg):
        msg = int.from_bytes(msg, 'big')
        msg = pow(msg, self.d, self.n)
        return int2bytes(msg)

def main():
    r = rsa()
    msg = b'thisispatrick'
    print('Plaintext message: ', msg)
    msg = r.encrypt_msg(msg)
    print('Encrypted message: ', msg)
    msg = r.decrypt_msg(msg)
    print('Decrypted message: ', msg)
