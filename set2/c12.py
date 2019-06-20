from c8 import get_repetitions
from c9 import pad_bytes, ecb_cipher
from c11 import detect_ecb_cbc

# It should be possible without the 'data' parameter, but this gives you an
# indication of a maximum block size
def find_blocksize(data, encrypt):
    for bsz in range(1, len(data)):
        reps0 = get_repetitions(encrypt(data), bsz)
        if get_repetitions(encrypt(2*bsz*b'X' + data), bsz) > reps0:
            break
    return bsz

def decode_ecb(data, encrypt, bsz):
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
    cph = ecb_cipher(np.random.bytes(16))

    # The only thing we can use for the attack is the unknown string and the
    # cipher function.
    unknown_str = b64decode(
     """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
        aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
        dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
        YnkK"""
    )

    bsz = find_blocksize(unknown_str, cph.encrypt)
    if detect_ecb_cbc(cph.encrypt(unknown_str), bsz):
        print(decode_ecb(unknown_str, cph.encrypt, bsz))
    else:
        print('Unknown string is not encrypted using ECB.')
