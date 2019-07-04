from c10 import cbc_cipher
from c18 import ctr_cipher

from base64 import b64decode
# Load data from the ECB exercise
with open('set2/c10data') as f:
    data = b64decode(f.read())
pt = cbc_cipher(b'YELLOW SUBMARINE', bytes(16)).decrypt(data)

ctr = ctr_cipher()

def edit(ct, key, offset, newtxt):
    pass
