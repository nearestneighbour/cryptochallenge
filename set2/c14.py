import numpy as np
from c09 import ecb_cipher
from c12 import decode_plaintext_ecb

class random_cipher(ecb_cipher):
    def __init__(self):
        super().__init__()
        self.prepend = np.random.bytes(np.random.randint(2 * self.bsz))

    def encrypt(self, data):
        if type(data) == str:
            data = data.encode()
        return super().encrypt(self.prepend + data)

def get_prepend_len(encrypt):
    l0 = len(encrypt(''))
    l1 = l0
    input = b''
    while l1==l0:
        input += b'X'
        l1 = len(encrypt(input))
    return l0 - len(input) + 1

def decode_plaintext_prep(data, encrypt, bsz):
    if type(data) == str:
        data = data.encode()
    prep_len = get_prepend_len(encrypt)
    input_prep_len = (bsz - (prep_len % bsz)) % bsz
    def encrypt_new(data):
        return encrypt(input_prep_len * b'X' + data)[prep_len+input_prep_len:]
    return decode_plaintext_ecb(data, encrypt_new, bsz)

def main():
    from base64 import b64decode
    from c12 import find_bsz_by_len

    unknown_str = b64decode(
     """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
        YnkK"""
    )
    cph = random_cipher()
    bsz = find_bsz_by_len(cph.encrypt)
    print(decode_plaintext_prep(unknown_str, cph.encrypt, bsz))
