import numpy as np
from c9 import ecb_cipher
from c12 import find_blocksize

class profile_manager:
    def __init__(self, key=None):
        self.cph = ecb_cipher(key if key else np.random.bytes(16))

    def parse_profile(self, url):
        return {prop.split('=')[0]: prop.split('=')[1] for prop in url.split('&')}

    def decrypt_profile(profile):
        return self.parse_profile(self.cph.decrypt(profile))

    def profile_for(self, addr):
        assert ('&' not in addr and '=' not in addr), "Stupid hacker"
        profile = 'email=' + addr + 'uid=10&role=user'
        return self.cph.encrypt(profile.encode())

def main():
    # We don't know the key, block size or encryption function
    # Only thing we know is the output of profile_for for a given input
    prf_manager = profile_manager()
    myprofile = prf_manager.profile_for('')
    bsz = find_blocksize(myprofile, prf_manager.profile_for)
    # Mail should be of such length that 'user' is at the start of a new block
    mail_length = (len(myprofile) - 5) % bsz
