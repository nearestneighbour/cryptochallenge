# I got tired of making webapps with Flask, especially of the testing, so this
# will be just a simulation of client-server communication. I did implement the
# SHA-256 algorithm myself, see c36_sha256.py.

import secrets
from c33 import diffiehellman, nist, numbytes
from c36_sha256 import sha256

N = nist; g = 2; k = 3; I = b'johnsmith@aol.com'; P = b'hunter2'
N = secrets.randbits(32)

class server:
    def __init__(self):
        self.dh = diffiehellman(N, g)
        self.salt = secrets.randbits(128).to_bytes(16, 'big') # not sure how long/big salt should be
        x = int(sha256().digest(self.salt + P).hex(), 16)
        # This is what's stored server-side instead of the actual password:
        self.v = pow(2, x, N)

    def receive_pubkey(self, msg):
        self.pk = msg['A']
        self.k = self.derive_session_key()
        return {'salt': self.salt, 'B': k*self.v + self.dh.publickey(True)}

    def derive_session_key(self):
        u = int(sha256().digest(self.pk + self.dh.publickey(True)).hex(), 16)
        s = pow(int.from_bytes(self.pk, 'big') * pow(self.v, u), self.dh.priv, N)
        return sha256().digest(s.to_bytes(numbytes(s), 'big'))

class client:
    def __init__(self):
        self.dh = diffiehellman(N, g)

    def exchange_pubkeys(self, s):
        msg = {'A': self.dh.publickey(True)}
        response = s.receive_pubkey(msg)
        self.salt = response['salt']
        self.pk = response['B']
        self.k = derive_session_key()

    def derive_session_key(self):
        u = int(sha256().digest(self.dh.publickey(True) + self.pk).hex(), 16)
        x = int(sha256().digest(self.salt + P).hex(), 16)
        s = pow(int.from_bytes(self.pk, 'big') - k * pow(g, x), self.dh.priv + u * x, N)
        return sha256().digest(s.to_bytes(numbytes(s), 'big'))

def main():
    s = server()
    c = client()
