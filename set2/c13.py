import numpy as np
from c8 import get_repetitions
from c9 import pad_bytes, ecb_cipher
from c12 import find_bsz_by_len

class profile_manager(ecb_cipher):
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

# Find how long the output is when input='' (removing padded bytes).
def find_cipher_len(encrypt):
    l0 = len(encrypt(''))
    l1 = l0
    npadded = 0
    while l1 == l0:
        npadded += 1
        l1 = len(encrypt(npadded * b'X'))
    return l0 + 1 - npadded

# Find how long the string is that prepends the user input
def find_prepend_len(encrypt, bsz):
    for i in range(bsz):
        out = encrypt((i + 2*bsz) * b'X')
        if get_repetitions(out, bsz) > 0:
            break
    if i == 0:
        return i
    for j in range(len(out) // bsz):
        if out[j*bsz : (j+1)*bsz] == out[(j+1)*bsz : (j+2)*bsz]:
            break
    return j * bsz - i

def main():
    # We don't know the key, block size or encryption function. The only
    # information we have is the output of profile_for for a given input.
    # (also we know the last 4 characters of the profile are 'user')
    prf_manager = profile_manager()

    # Set address length such that 'user' is at the start of a new  block so we
    # can cut off the first part, which ends with '&role='.
    bsz = find_bsz_by_len(prf_manager.profile_for)
    cph_len = find_cipher_len(prf_manager.profile_for) - 4 # len('user')
    input_len = int(bsz * np.ceil(cph_len / bsz)) - cph_len
    part1 = prf_manager.profile_for(input_len * b'X')[:-bsz]

    # Generate address so that 'admin' is at the start of the 2nd block so we
    # can paste it after the first part. Make sure the rest of the 2nd block is
    # padded so it is a legitimate "last" block.
    prep_len = find_prepend_len(prf_manager.profile_for, bsz)
    addr_len = int(bsz * np.ceil(prep_len / bsz)) - prep_len
    addr = addr_len * b'X' + pad_bytes('admin', bsz)
    part2 = prf_manager.profile_for(addr)[(prep_len+addr_len):(prep_len+addr_len+bsz)]

    # Paste two parts together and decrypt profile.
    ciphertext = part1 + part2
    print(prf_manager.decrypt_profile(ciphertext))
