from c8 import get_repetitions
from c9 import pad_bytes, ecb_cipher
from c11 import detect_ecb_cbc

# Find the block size of a block cipher by counting the number of repetitions.
# encrypt parameter should be an encryption function handle
def find_bsz_by_reps(encrypt, max_bsz = 64, min_bsz = 2):
    reps = 0
    bsz = min_bsz - 1
    while reps == 0:
        bsz += 1
        if bsz > max_bsz:
            return -1
        reps = get_repetitions(encrypt(2*bsz*b'X'), bsz)
    return bsz

# Find the block size of a block cipher by counting how much data is padded.
# This will be used in future challenges
def find_bsz_by_len(encrypt):
    l0 = len(encrypt(''))
    l1 = l0
    n = 0
    while l1 == l0:
        n += 1
        l1 = len(encrypt(n * b'X'))
    return l1 - l0

def decode_plaintext_ecb(data, encrypt, bsz):
    output = ''
    prep = (bsz-1) * b'X'
    for i in range(len(data)):
        realblock = encrypt(prep + bytes([data[i]]))
        for j in range(256):
            block = encrypt(prep + bytes([j]))
            if block == realblock:
                output += chr(j)
                break
    return output

def main():
    import numpy as np
    from base64 import b64decode
    # This part should be unknown, i.e. we don't know the key, the block size or
    # the content of the encryption function
    cph = ecb_cipher()

    # The only thing we can use for the attack is the unknown string and the
    # cipher function.
    unknown_str = b64decode(
     """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
        YnkK"""
    )

    bsz = find_bsz_by_reps(cph.encrypt)
    if bsz == -1:
        print('Could not detect block size, either block size > 64 or cipher is not ECB')
        return
    if detect_ecb_cbc(cph.encrypt(unknown_str), bsz):
        print(decode_ecb(unknown_str, cph.encrypt, bsz))
    else:
        print('Unknown string is not encrypted using ECB.')
