import numpy as np
import requests, secrets, sys
sys.path.append('set2')
sys.path.append('set4')
from c10 import cbc_cipher
from c28 import sha1
from c33 import diffiehellman, numbytes

def encrypt_msg(s, msg):
    key = sha1().digest(s)[:16]
    iv = np.random.bytes(16)
    return (cbc_cipher.encrypt_cbc(msg, key=key, iv=iv) + iv).hex()

def decrypt_msg(s, msg):
    msg = bytes.fromhex(msg)
    iv = msg[-16:]
    msg = msg[:-16]
    key = sha1().digest(s)[:16]
    return cbc_cipher.decrypt_cbc(msg, key=key, iv=iv).decode()

def main(port=5000):  # port 5000 for echo bot, 5001 for MITM
    url = 'http://localhost:{}/test'.format(port)
    p = secrets.randbits(1024); g = 3
    dh = diffiehellman(p, g)
    msg_pt = 'This is a message'
    print('Message: ', msg_pt)

    # Send DH parameters and receive public key
    response = requests.get(url + '?p={}&g={}&pk={}'.format(p, g, dh.publickey().hex()))
    if response.status_code != 200:
        print('Status code-1 {}: '.format(response.status_code), response.text)
        return
    pk = int(response.json()['pk'], 16)
    msg_ct = encrypt_msg(dh.secret(pk), msg_pt)

    # Send encrypted message and decrypt echo
    response = requests.get(url + '?msg=' + msg_ct)
    if response.status_code != 200:
        print('Status_code-2 {}: '.format(response.status_code), response.text)
        return
    msg_ct = response.json()['msg']
    try:
        msg_pt = decrypt_msg(dh.secret(pk), msg_ct)
    except:
        print('Client could not decrypt message')
    else:
        print('Echo: ', msg_pt)
