import numpy as np
from c3 import decrypt_single_xor
from c5 import encrypt_repeat_xor

def edit_distance(a,b):
    if type(a) == str:
        a = [ord(i) for i in a]
    if type(b) == str:
        b = [ord(i) for i in b]
    return sum([bin(x^y).count('1') for x,y in zip(a,b)])

def find_keysize(data, keysizes = range(2,41)):
    dist = np.zeros((len(keysizes)))
    for i in range(len(keysizes)):
        ks = keysizes[i]
        r = range(0, len(data)-ks, ks)
        for j in r:
            dist[i] += edit_distance(data[j : j+ks], data[j+ks : j+ks+ks]) / (ks*len(r))
    return dist, keysizes[np.argmin(dist)]

def decrypt_repeat_xor(data, ks):
    blocks = [data[i : i+ks] for i in range(0,len(data),ks)]
    pad = 0
    while len(blocks[-1]) < ks:
        pad += 1
        blocks[-1] += b'\x00'
    blocks = [bytes([i[j] for i in blocks]) for j in range(ks)]
    key = []
    for b in blocks:
        _, c = decrypt_single_xor(b)
        key += [c]
    msg = encrypt_repeat_xor(data, key)
    if pad > 0:
        msg = msg[:-pad]
    return msg, bytes(key)

def main():
    from base64 import b64decode
    with open('set1/c6data') as f:
        data = b64decode(f.read())

    _, ks = find_keysize(data)
    msg, key = decrypt_repeat_xor(data, ks)
    print('Message: ', msg.decode())
    print('Key: ', key.decode())
