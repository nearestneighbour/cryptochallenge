# run with the command:
# FLASK_APP=set5/c34_server.py flask run

from flask import Flask, request, jsonify
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
        pk = int(request.args['A'])
        return jsonify({'B': dh.publickey()})

    elif 'msg' in request.args:
        if dh == None:
            return jsonify({'error': 'Send DH parameters first'})

        msg_ct = request.args['msg']
        msg_pt = decrypt_msg(dh.secret(pk), msg)
        msg ct = encrypt_msg(dh.secret(pk), msg)
        return jsonify({'msg': msg_ct})

    return 'Invalid request', 400
