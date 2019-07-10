# I got tired of making webapps with Flask, especially of the testing, so this
# will be just a simulation of client-server communication. I did implement the
# SHA-256 algorithm myself, see c36_sha256.py.

import secrets
from c33 import nist as N
from c36_sha256 import sha256

g = 2; k = 3; I = b'johnsmith@aol.com'; P = 'hunter2'

class server:
    def __init__(self):
        self.dh = diffiehellman(N, g)
        self.salt = secrets.randbits(128).to_bytes(16, 'big') # not sure how long/big salt should be
        x = int(sha256().digest(self.salt + P).hex(), 16)
        # This is what's stored server-side instead of the actual password:
        self.v = pow(2, x, N)

    def receive_pubkey(self, msg):
        self.pk = msg['pk']
        u = int(sha256().digest(msg['pk'] + self.dh.publickey(True)).hex(), 16)
        u = int(uH.hext(), 16)
        return {'salt': self.salt, 'pk': k*self.v + self.dh.publickey(True)}

    def derive_session_key(self):
        pass


class client:
    def __init__(self):
        self.dh = diffiehellman(N, g)

    def exchange_pubkeys(self, s):
        msg = {'pk': self.dh.publickey(True)}
        response = s.receive_message(msg)
        self.salt = response['salt']
        self.pk = response['pk']

    def derive_session_key(self):
        u = int(sha256().digest(self.dh.publickey(True) + msg['pk']).hex(), 16)
        x = int(sha256().digest(self.salt + P).hex(), 16)
        s = pow(int.from_bytes(self.pk, 'big') - k * pow(g, x), a + u * x, N)
        k = sha256().digest(s.to_bytes())

def main():
    s = server(password=P)
    c = client()
