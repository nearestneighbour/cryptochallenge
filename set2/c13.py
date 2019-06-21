import numpy as np
from c9 import pad_bytes, ecb_cipher
from c12 import find_bsz_by_len

class profile_manager(ecb_cipher):
    #def __init__(self, key=None):
    #    self.cph = ecb_cipher(key if key else np.random.bytes(16))

    def parse_profile(self, url):
        if type(url) == bytes:
            url = url.decode()
        return {prop.split('=')[0]: prop.split('=')[1] for prop in url.split('&')}

    def decrypt_profile(self, profile):
        return self.parse_profile(self.decrypt(profile))

    def profile_for(self, addr):
        if type(addr) == bytes:
            addr = addr.decode()
        assert ('&' not in addr and '=' not in addr), "Stupid hacker"
        profile = 'email=' + addr + '&uid=10&role=user'
        return self.encrypt(profile.encode())

# Find how long the encrypted string is when input='' (excluding padded bytes)
def find_basestr_len(encrypt):
    l0 = len(encrypt(''))
    l1 = l0
    npadded = 0
    while l1 == l0:
        npadded += 1
        l1 = len(encrypt(npadded * b'X'))
    return l0 + 1 - npadded

# We don't know the key, block size or encryption function
# Only thing we know is the output of profile_for for a given input
prf_manager = profile_manager()
bsz = find_bsz_by_len(prf_manager.profile_for)

# Generate mail address of length such that 'user' is at the start of a new
# block so we can extract the first part of our cut-and-paste
cph_len = find_basestr_len(prf_manager.profile_for) - 4
addr_len = int(bsz * np.ceil(cph_len / bsz)) - cph_len
q1 = prf_manager.profile_for(addr_len * 'X')[:-bsz]

# Let's put 'admin' at the start of the 2nd block so we can cut and paste it
# after the first part
addr_prepend = (bsz - 6) * b'X'
addr = addr_prepend + pad_bytes('admin', bsz)
q2 = prf_manager.profile_for(addr)[bsz:2*bsz]
