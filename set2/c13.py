import numpy as np
from c9 import ecb_cipher
from c12 import find_bsz_by_len

class profile_manager:
    def __init__(self, key=None):
        self.cph = ecb_cipher(key if key else np.random.bytes(16))

    def parse_profile(self, url):
        return {prop.split('=')[0]: prop.split('=')[1] for prop in url.split('&')}

    def decrypt_profile(profile):
        return self.parse_profile(self.cph.decrypt(profile))

    def profile_for(self, addr):
        if type(addr) == bytes:
            addr = addr.decode()
        assert ('&' not in addr and '=' not in addr), "Stupid hacker"
        profile = 'email=' + addr + '&uid=10&role=user'
        return self.cph.encrypt(profile.encode())

# Find how long the encrypted string is when input='' (excluding padded bytes)
def find_basestr_len(encrypt, bsz):
    l0 = len(encrypt(''))
    l1 = l0
    npadded = 0
    while l1 == l0:
        npadded += 1
        l1 = len(encrypt(npadded * b'X'))
    return l0, l1, npadded

def main():
    # We don't know the key, block size or encryption function
    # Only thing we know is the output of profile_for for a given input
    prf_manager = profile_manager()
    bsz = find_bsz_by_len(prf_manager.profile_for)
    # Generate mail address of length such that 'user' is at the start of a new block
    #myprofile = prf_manager.profile_for('')
    #nblocks = myprofile()
    #mail_length = (len(prf_manager.profile_for('')) - 5) % bsz
