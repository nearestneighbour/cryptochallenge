import numpy as np
from c7 import encrypt_ecb
from c8 import get_repetitions
from c9 import pad_bytes
from c10 import encrypt_cbc

def encrypt_random(msg):
    pre = np.random.bytes(np.random.randint(5,11))
    post = np.random.bytes(np.random.randint(5,11))
    msg = pad_bytes(pre + msg + post, 16)
    if np.random.randint(2) == 0:
        return encrypt_ecb(msg, np.random.bytes(16))
    else:
        iv = np.random.bytes(16)
        return encrypt_cbc(msg, np.random.bytes(16), np.random.bytes(16))

def detect_ecb_cbc(msg, cph):
    # Remove bytes that are definitely not part of the message
    #cph = cph[5:-5]
    #left = len(cph) - len(msg)
    #cph = cph[(left-5):(5-left)]
    reps = [get_repetitions(cph, 16)]
    for i in range(len(cph) % 16):
        reps += [get_repetitions(cph[i:], 16)]
    return 'ecb' if max(reps) > 0 else 'cbc'

if __name__ == '__main__':
    msg = ('X' * 64).encode()
    print(detect_ecb_cbc(msg, encrypt_random(msg)))
