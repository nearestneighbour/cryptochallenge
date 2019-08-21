# run with command: python3 set5/c38_mitm.py

from flask import Flask, request, jsonify
import sys
from c36_sha256 import sha256
from c36_client import N, g, int2bytes

pass_list = ['hunter','huntera','hunbert','hunter1','hunter2']
salt = b'\x00'
u = 1; b = 1 # then B = g = 2
pk = None; hmac = None
app = Flask(__name__)

def dict_attack():
    found = False
    for p in pass_list:
        v = pow(g, sha256().intdigest(salt + p.encode()), N)
        s = pow(pk * pow(v, u, N), b, N)
        k = sha256().digest(int2bytes(s))
        if sha256().hmac(salt, k).hex() == hmac:
            found = True
            break
    return p if found else None

@app.route('/test', methods=['GET'])
def handle_request():
    if 'pk' in request.args:
        global pk
        pk = int(request.args['pk'], 16)
        return jsonify({'salt': '00', 'pk': '02', 'u': '1'})

    elif 'hmac' in request.args:
        global hmac
        hmac = request.args['hmac']
        P = dict_attack()
        if P:
            print('Password: ', P, file=sys.stderr)
        return 'HMAC OK', 200

    return 'Invalid request', 400

app.run()
