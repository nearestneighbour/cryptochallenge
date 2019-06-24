import numpy as np
from c9 import ecb_cipher




from base64 import b64decode
unknown_str = b64decode(
 """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK"""
)
cph = ecb_cipher()
def encrypt_random(data):
    prep = np.random.bytes(np.random.randint(50))
    return cph.encrypt(prep + data + unknown_str)
