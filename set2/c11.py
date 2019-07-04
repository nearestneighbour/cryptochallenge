import numpy as np
from c08 import get_repetitions
from c09 import ecb_cipher
from c10 import cbc_cipher

def encrypt_random(data, bsz):
    pre = np.random.bytes(np.random.randint(5,11))
    post = np.random.bytes(np.random.randint(5,11))
    data = pre + data + post
    if np.random.randint(2) == 0:
        return ecb_cipher.encrypt_ecb(data)
    else:
        return cbc_cipher.encrypt_cbc(data)

def detect_ecb_cbc(output, bsz):
    reps = [get_repetitions(output, bsz)]
    for i in range(len(output) % bsz):
        reps += [get_repetitions(output[i:], bsz)]
    return 'ecb' if max(reps) > 0 else 'cbc'

def main():
    bsz = 16
    data = 4 * bsz * b'X'
    print(detect_ecb_cbc(encrypt_random(data, bsz), bsz))
