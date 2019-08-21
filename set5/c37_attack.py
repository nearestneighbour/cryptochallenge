# reuse server from challenge 36, run with command:
# python3 set5/c36_server.py

# When the server receives a PK that is 0, the session key will also be 0. If
# PK=N or PK=N**2, it will also be 0.

import requests
from c36_sha256 import sha256

def main(pk_value): # pk_value can be e.g. 0, N or N**2
    pk_value = hex(pk_value)[2:]
    if len(pk_value) < 2:
        pk_value = '0' + pk_value

    url = 'http://localhost:5000/test'
    resp = requests.get(url + '?pk=' + pk_value)
    pk = int(resp.json()['pk'], 16)
    salt = bytes.fromhex(resp.json()['salt'])

    key = sha256().digest(b'\x00')
    hmac = sha256().hmac(salt, key)

    resp = requests.get(url + '?hmac=' + hmac.hex())
    print(resp.text)
