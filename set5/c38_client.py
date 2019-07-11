import requests
from c33 import diffiehellman
from c36_sha256 import sha256
from c36_client import N, g, P, intdigest, int2bytes

class client(diffiehellman):
    def session_key(self, salt, pk, u):
        self.salt = salt
        x = intdigest(salt + P)
        s = pow(pk, self.priv + u * x, N)
        self.key = sha256().digest(int2bytes(s))

    def hmac(self):
        return sha256().hmac(self.salt, self.key)

def main():
    c = client(N, g)
    url = 'http://localhost:5000/test'
    resp = requests.get(url + '?pk=' + c.publickey().hex())
    pk = int(resp.json()['pk'], 16)
    salt = bytes.fromhex(resp.json()['salt'])
    u = int(resp.json()['u'])
    c.session_key(salt, pk, u)
    resp = requests.get(url + '?hmac=' + c.hmac().hex())
    print(resp.text)
