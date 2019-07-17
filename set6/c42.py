from c28 import sha1
from c33 import numbytes
from c39 import rsa
from c40 import cube_root

sha1_asn1 = bytes.fromhex('30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14')

# Padding according to https://tools.ietf.org/html/rfc2313 section 8.1
def pad_pkcs1(msg, k):
    n_ff = k - 3 - len(msg)
    return b'\x00\x01' + n_ff * b'\xff' + b'\x00' + msg

class rsa_sign(rsa):
    def __init__(self, **kwargs):
        self.asn1 = kwargs.pop('asn1', sha1_asn1)
        self.hashfunc = kwargs.pop('hashfunc', sha1().digest)
        super().__init__(kwargs)

    def sign(self, msg, tobytes=False):
        hash = self.hashfunc(msg)
        block = pad_pkcs1(self.asn1 + hash, k = numbytes(self.n))
        return self.decrypt(block, tobytes)

    def verify_unsafe(self, sig, msg):
        msghash = self.hashfunc(msg)
        block = b'\x00' + self.encrypt(sig, tobytes = True)
        asn_start = block[2:].index(b'\x00') + 3
        hash_start = asn_start + len(self.asn1)
        sighash = block[hash_start : hash_start + len(msghash)]

        assert block[:2] == b'\x00\x01', "Invalid padding"
        assert b'\x00' in block[2:], "Invalid padding"
        assert block[asn_start:hash_start] == self.asn1, "Invalid ASN1 info"
        assert sighash == msghash, "Invalid signature hash"
        return "Valid signature"

def main():
    # Goal: forge a valid signature without using rsa_sign.sign(msg)
    # Create signature block, pad with a bunch of zeros, take cube root
    msg = b'hi mom'
    msghash = sha1().digest(msg)
    sig = b'\x00\x01\xff\x00' + sha1_asn1 + msghash
    sig += (128-len(sig)) * b'\x00'
    sigint = cube_root(int.from_bytes(sig, 'big'))
    print(rsa_sign().verify_unsafe(sigint, msg))
