# run with command: FLASK_APP=c31_server.py flask run
from flask import Flask, request
from time import sleep
import numpy as np
from c28 import sha1

key = np.random.bytes(16)
app = Flask(__name__)

def insecure_compare(sig1, sig2):
    for b1, b2 in zip(sig1, sig2):
        if b1 != b2:
            return False
        sleep(0.05)
    return len(sig1) == len(sig2)

@app.route('/test', methods=['GET'])
def handle_request():
    file = request.args.get('file')
    try:
        sig = bytes.fromhex(request.args.get('signature'))
    except:
        sig = None

    if not (file and sig):
        return "Provide valid filename and signature", 400

    realsig = sha1().auth(file.encode(), key)
    return ("Valid", 200) if insecure_compare(realsig, sig) else ("Invalid", 500)