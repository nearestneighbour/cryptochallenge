# Inspired by:
# https://laconicwolf.com/2018/10/30/cryptopals-challenge-8-detect-ecb-mode-encryption/

import numpy as np

def get_repetitions(data, bsz):
    blocks = [data[i:i+bsz] for i in range(0,len(data),bsz)]
    reps = len(blocks)-len(set(blocks))
    return reps

if __name__ == '__main__':
    with open('c8data') as f:
        data = f.readlines()
        data = [bytes.fromhex(d.strip()) for d in data]

    repetitions = np.zeros((len(data)))
    for i in range(len(data)):
        repetitions[i] = get_repetitions(data[i], 16)
    print(data[np.argmax(repetitions)].hex())
