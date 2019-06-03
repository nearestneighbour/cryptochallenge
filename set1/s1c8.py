# Inspired by:
# https://laconicwolf.com/2018/10/30/cryptopals-challenge-8-detect-ecb-mode-encryption/

import numpy as np

with open('s1c8data') as f:
    data = f.readlines()
    data = [bytes.fromhex(d.strip()) for d in data]

bsz = 16
blocks = [[d[i:i+bsz] for i in range(0,len(d),bsz)] for d in data]

repetitions = np.zeros((len(blocks)))
for i in range(len(blocks)):
    repetitions[i] = len(blocks[i])-len(set(blocks[i]))

result = data[np.argmax(repetitions)]
