import numpy as np

from c06 import find_keysize, decrypt_repeat_xor
from c18 import ctr_cipher

from base64 import b64decode
with open('set3/c19data') as f:
    data = [b64decode(line.strip()) for line in f.readlines()]

cph = ctr_cipher(prefix=bytes(8))
data_enc = [cph.encrypt(line) for line in data]

# Pad lines so they have equal length and still same keystream
m = max([len(line) for line in data_enc])
add = [m-len(line) for line in data_enc]
maxline = np.argmin(add)
data_padded = [line+data_enc[maxline][-idx:] for line,idx in zip(data_enc,add)]
data_padded[maxline] = data_padded[maxline][:m]

data_string = b''.join([line for line in data_padded])
txt, _ = decrypt_repeat_xor(data_string, m)

#dist = np.zeros(n-1)
#for i in range(2,n+1):
#    blocks = b''.join([line[:n] for line in data if len(line)])
#    dist[i-2], _ = find_keysize(blocks, [i])
#ksz = np.argmin(dist) + 2


#txt, key = decrypt_repeat_xor(blockstr, len(data_trunc[0]))
