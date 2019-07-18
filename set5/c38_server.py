# run with the command: FLASK_APP=set5/c38_server.py flask run

from flask import Flask, request, jsonify
from random import getrandbits
from c33 import diffiehellman
from c36_sha256 import sha256
from c36_client import N, g, P, intdigest, int2bytes

class server_srp(diffiehellman):
    def __init__(self):
        super().__init__(N, g)
        self.salt = getrandbits(128).to_bytes(16, 'big')
        self.v = pow(g, intdigest(self.salt + P), N)
        self.u = getrandbits(128)

    def session_key(self, pk):
        s = pow(int(pk, 16) * pow(self.v, self.u, N), self.priv, N)
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
        return jsonify({'salt': s.salt.hex(), 'pk': s.publickey().hex(), 'u': s.u})
    elif 'hmac' in request.args:
        hmac = request.args['hmac']
        return ('HMAC OK', 200) if hmac==s.hmac().hex() else ('HMAC NOT OK', 500)

    return 'Invalid request', 400
