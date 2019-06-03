# This can be done with openssl using the command:
# openssl aes-128-ecb -d -a -in s1c7data -K 59454c4c4f57205355424d4152494e45
# where 59454c4c4f57205355424d4152494e45 is the hex-encoded key YELLOW SUBMARINE

from base64 import b64decode
from Crypto.Cipher import AES

with open('s1c7data') as f:
    data = b64decode(f.read())

key = 'YELLOW SUBMARINE'
cph = AES.new(key, AES.MODE_ECB)
result = cph.decrypt(data)
