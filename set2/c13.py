import numpy as np
from Crypto.cipher import AES

def parse_keyval(url):
    props = url.split('&')
    res = {}
    for p in props:
        res[p.split('=')[0]] = p.split('=')[1]
    return res

def profile_for(email):
    assert (email.find('&') == -1 & email.find('=') == -1), "Stupid hacker"
    return 'email=' + email + 'uid=10&role=user'

key = np.bytes.random(16)
cph = AES.new(key, AES.MODE_ECB)

def encrypt_profile(profile):
    return cph.encrypt(profile)

def decrypt_profile(profile):
    return parse_keyval(cph.decrypt(profile))
