# run server with command: FLASK_APP=c31_server.py flask run

import requests as r
from time import time
import numpy as np

def attack(emptyurl, filename):
    url = emptyurl + '?file=' + filename + '&signature='
    sig = b''
    for i in range(20):
        for j in range(256):
            testsig = sig + bytes([j])
            st = time()
            r.get(url +  testsig.hex())
            t = time() - st
            if t > (len(sig) + 1) * 0.05:
                sig += bytes([j])
                break
        assert len(sig) == i+1, 'Failed to find next byte'
        print('Discovered {} out of 20 bytes, signature so far: {}'.format(i+1, sig.hex()))
    return sig

def main():
    import numpy as np
    emptyurl = 'http://localhost:5000/test'
    # Discover baseline connection time
    t = []
    for i in range(10):
        st = time()
        r.get(emptyurl)
        t += [time() - st]
    print('Baseline request duration: ', np.mean(t))
    print('Standard deviation: ', np.std(t))
    # Requests should take 50ms longer for every signature byte that is correct.
    # Request duration standard deviation is pretty low, so it should be easy to
    # figure out how many bytes are correct from the request duration alone
    # without having to resort to averaging multiple rounds etc.
    attack(emptyurl, 'foo')
