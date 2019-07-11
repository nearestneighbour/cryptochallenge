# run server with the command:
# FLASK_APP=set5/c34_server.py flask run

import requests
from c33 import diffiehellman, nist, numbytes
from c36_sha256 import sha256

N = nist; g = 2; k = 3; P = b'hunter2'

def intdigest(data):
    return int(sha256().digest(data).hex(), 16)

def int2bytes(x):
    return x.to_bytes(numbytes(x), 'big')

class client(diffiehellman):
    def session_key(self, salt, pk):
        self.salt = salt
        u = intdigest(self.publickey() + int2bytes(pk))
        x = intdigest(salt + P)
        s = pow(pk - k * pow(g, x, N), self.priv + u * x, N)
        self.key = sha256().digest(int2bytes(s))

    def hmac(self):
        return sha256().hmac(self.salt, self.key)

def main():
    c = client(N, g)
    url = 'http://localhost:5000/test'
    resp = requests.get(url + '?pk=' + c.publickey().hex())
    pk = int(resp.json()['pk'], 16)
    salt = bytes.fromhex(resp.json()['salt'])
    c.session_key(salt, pk)
    resp = requests.get(url + '?hmac=' + c.hmac().hex())
    print(resp.text)
