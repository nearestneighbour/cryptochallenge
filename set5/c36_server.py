from flask import Flask, request, jsonify
from random import getrandbits
from c33 import diffiehellman
from c36_sha256 import sha256
from c36_client import N, g, k, P, int2bytes

class server_srp(diffiehellman):
    def __init__(self):
        super().__init__(N, g)
        self.salt = getrandbits(128).to_bytes(16, 'big')
        # This is what's stored server-side instead of the actual password:
        self.v = pow(g, sha256().intdigest(self.salt + P), N)
        self.key = None

    def publickey(self, tobytes=True):
        if tobytes:
            return int2bytes(k * self.v + super().publickey(False))
        return k * self.v + super().publickey(False)

    def session_key(self, pk):
        u = sha256().intdigest(bytes.fromhex(pk) + self.publickey())
        s = pow(int(pk, 16) * pow(self.v, u, N), self.priv, N)
        self.key = sha256().digest(int2bytes(s))

    def hmac(self):
        return sha256().hmac(self.salt, self.key)

s = server_srp()
app = Flask(__name__)

@app.route('/test', methods=['GET'])
def handle_request():
    global s
    if 'pk' in request.args:
        s.session_key(request.args['pk'])
        return jsonify({'salt': s.salt.hex(), 'pk': s.publickey().hex()})
    elif 'hmac' in request.args:
        hmac = request.args['hmac']
        return ('HMAC OK', 200) if hmac==s.hmac().hex() else ('HMAC NOT OK', 500)

    return 'Invalid request', 400

app.run()
