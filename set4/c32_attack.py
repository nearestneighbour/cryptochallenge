# reuse server from challenge 31, run with command:
# python3 set4/c31_server.py

import requests as r
from time import time
import numpy as np

def timeurl(url, rounds=10):
    t = []
    for i in range(rounds):
        st = time()
        r.get(url)
        t += [time() - st]
    return np.mean(t)

file = 'foo'
url = 'http://localhost:5000/test' + '?file=' + file + '&signature='
sig = b''

for i in range(20):
    m = []
    for j in range(256):
        testsig = sig + bytes([j])
        m += [timeurl(url + testsig.hex())]
    sig += bytes([np.argmax(m)])
    print('Discovered {} out of 20 bytes, signature so far: {}'.format(i+1, sig.hex()))
