# run with the command:
# FLASK_APP=set5/c34_mitm.py flask run --port 5001

from flask import Flask, request, jsonify
import requests, sys
from c33 import diffiehellman
from c34_client import numbytes, encrypt_msg, decrypt_msg

p = None; g = None
server = 'http://localhost:5000/test'
app = Flask(__name__)

@app.route('/test', methods=['GET'])
def handle_request():
    global p, g, url
    if 'p' in request.args:
        p = int(request.args['p'])
        g = int(request.args['g'])

        requests.get(server + '?p={}&g={}&pk={}'.format(p, g, p))
        return jsonify({'pk': p})

    elif 'msg' in request.args:
        msg_ct1 = request.args['msg']
        response = requests.get(server + '?msg=' + msg_ct1)

        if response.status_code != 200:
            return response.text, response.status_code

        msg_ct2 = response.json()['msg']
        print('Client->Server: ', decrypt_msg(b'\x00', msg_ct1), file=sys.stderr)
        print('Server->Client: ', decrypt_msg(b'\x00', msg_ct2), file=sys.stderr)
        fake_msg_ct = encrypt_msg(b'\x00', 'I can hear you')
        return jsonify({'msg': fake_msg_ct})

    return 'Invalid request', 400 # Copy server behaviour
