import numpy as np
from base64 import b64decode
from Crypto.Cipher import AES
from c8 import get_repetitions
from c9 import pad_bytes
from c11 import detect_ecb_cbc

def find_blocksize(data, cipher):
    # cipher should be an encryption function
    for bsz in range(1,int(len(data)/2)):
        reps0 = get_repetitions(cipher(data), bsz)
        if get_repetitions(cipher(2 * bsz * b'X' + data), bsz) > reps0:
            break
    return bsz

def find_string(data, cipher, bsz):
    output = ''
    prep = (bsz-1) * b'X'
    for i in range(len(data)):
        realblock = cipher(prep + bytes([data[i]]))
        for j in range(256):
            block = cipher(prep + bytes([j]))
            if block == realblock:
                output += chr(j)
                break
    return output

if __name__ == '__main__':
    # This part should be unknown, i.e. we shouldn't know how the encryption works
    # We don't know the key and cipher function (but we can call it)
    unknown_str = pad_bytes(b64decode("""Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK"""), 16)
    key = np.random.bytes(16)
    def cipherfunc(data):
        cph = AES.new(key, AES.MODE_ECB)
        return cph.encrypt(pad_bytes(data, 16))

    # This part is where we try to figure out the encryption. The only thing we
    # can use is the unknown string and the encryption function.
    bsz = find_blocksize(unknown_str, cipherfunc)
    if not detect_ecb_cbc(unknown_str, cipherfunc(unknown_str), bsz):
        print('Unknown string is not encrypted using ECB.')
    else:
        print(find_string(unknown_str, cipherfunc, bsz))
