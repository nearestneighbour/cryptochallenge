# run with the command:
# FLASK_APP=set5/c34_server.py flask run --port 5000

from flask import Flask, request, jsonify
import sys
from c33 import diffiehellman
from c34_client import numbytes, encrypt_msg, decrypt_msg

dh = None
pk = None
app = Flask(__name__)

@app.route('/test', methods=['GET'])
def handle_request():
    global dh, pk
    if 'p' in request.args:
        dh = diffiehellman(int(request.args['p']), int(request.args['g']))
        pk = int(request.args['pk'])
        return jsonify({'pk': dh.publickey()})

    elif 'msg' in request.args:
        if dh == None:
            return 'Send DH parameters first', 400

        msg_ct = request.args['msg']
        try:
            msg_pt = decrypt_msg(dh.secret(pk), msg_ct)
        except:
            return 'Server could not decrypt message', 500
        print(msg_pt, file=sys.stderr)
        msg_ct = encrypt_msg(dh.secret(pk), msg_pt)
        return jsonify({'msg': msg_ct})

    return 'Invalid request', 400
