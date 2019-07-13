from c36_client import int2bytes
from c39 import rsa, invmod

def decrypt_unpadded(ct, oracle):
    e, n = oracle.publickey()
    ct_new = (pow(2, e, n) * ct) % n # s = 2
    pt_new = oracle.decrypt(ct_new)
    pt = pt_new * invmod(2, n) % n
    return int2bytes(pt)

def main():
    r = rsa()
    ct = r.encrypt(b'Never gonna give you up')
    print('Decrypted message: ', decrypt_unpadded(ct, r))
