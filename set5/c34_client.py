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
    return cbc_cipher.decrypt_cbc(msg, key=key, iv=iv).decode()

def main():
    url = 'http://localhost:5000/test' # port 5000 for echo bot, 5001 for mitm
    p = 100
    g = 3
    dh = diffiehellman(p, g)
    msg_pt = 'This is a message'
    print('Message: ', msg_pt)

    response = r.get(url + '?p={}&g={}&pk={}'.format(p, g, dh.publickey()))
    if response.status_code != 200:
        print('Status code {}: '.format(response.status_code), response.text)
    pk = response.json()['pk']
    msg_ct = encrypt_msg(dh.secret(pk), msg_pt)
    response = r.get(url + '?msg=' + msg_ct)
    if response.status_code != 200:
        print('Status_code {}: '.format(response.status_code), response.text)
    msg_ct = response.json()['msg']
    msg_pt = decrypt_msg(dh.secret(pk), msg_ct)
    print('Echo: ', msg_pt)

def submit(msg):
    return r.get('http://localhost:5000/test?msg='+msg)
