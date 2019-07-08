import numpy as np
import requests as r
import sys
sys.path.append('set2')
sys.path.append('set4')
from c10 import cbc_cipher
from c28 import sha1
from c33 import diffiehellman

def numbytes(s):
    n = 0
    while s > 0:
        s >>= 8
        n += 1
    return n

def encrypt_msg(s, msg):
    key = sha1().digest(s.to_bytes(numbytes(s), 'big'))[:16]
    iv = np.random.bytes(16)
    return (cbc_cipher.encrypt_cbc(msg, key=key, iv=iv) + iv).hex()

def decrypt_msg(s, msg):
    msg = bytes.fromhex(msg)
    iv = msg[-16:]
    msg = msg[:-16]
    key = sha1().digest(s.to_bytes(numbytes(s), 'big'))[:16]
    return cbc_cipher.decrypt_cbc(msg, key=key, iv=iv)

def main():
    dh = diffiehellman(100, 3)
    pk = r.get('http://localhost:5000/test?p=100&g=3&A=' + str(dh.publickey())).json()['B']
    msg = encrypt_msg(dh.secret(pk), 'abcdefg')
    return dh, pk, msg

def submit(msg):
    return r.get('http://localhost:5000/test?msg='+msg)
