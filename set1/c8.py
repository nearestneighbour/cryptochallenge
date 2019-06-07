# Inspired by:
# https://laconicwolf.com/2018/10/30/cryptopals-challenge-8-detect-ecb-mode-encryption/

import numpy as np

def get_repetitions(data, bsz):
    blocks = [[d[i:i+bsz] for i in range(0,len(d),bsz)] for d in data]
    reps = np.zeros((len(blocks)))
    for i in range(len(blocks)):
        reps[i] = len(blocks[i])-len(set(blocks[i]))
    return reps

if __name__ == '__main__':
    with open('c8data') as f:
        data = f.readlines()
        data = [bytes.fromhex(d.strip()) for d in data]

    bsz = 16
    repetitions = get_repetitions(data, bsz)
    print(data[np.argmax(repetitions)])
