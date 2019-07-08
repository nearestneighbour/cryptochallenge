# run with the command:
# FLASK_APP=set5/c34_mitm.py flask run --port 5001

from flask import Flask, request, jsonify
import requests as r
from c33 import diffiehellman
from c34_client import numbytes, encrypt_msg, decrypt_msg

p = None; g = None
url = 'http://localhost:5000/test'
messages = []
app = Flask(__name__)

@app.route('/test', methods=['GET'])
def handle_request():
    global p, g, messages, url
    if 'p' in request.args:
        p = int(request.args['p'])
        g = int(request.args['g'])
        pkA = int(request.args['pk']) # necessary or not?
        response = r.get(url + '?p={}&g={}&pk={}'.format(p, g, p))
        pkB = response.json()['pk'] # necessary or not?
        return jsonify({'pk': p})

    elif 'msg' in request.args:
        messages += [request.args['msg']]

        response = r.get(url + '?msg=' + messages[-1])
        if response.status_code != 200:
            return response.text, response.status_code

        messages += [response.json()['msg']]
        return jsonify({'msg': messages[-1]})

    return 'Invalid request', 400
