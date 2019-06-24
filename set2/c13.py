from c8 import get_repetitions
from c9 import ecb_cipher

class profile_manager(ecb_cipher):
    def parse_profile(self, url):
        if type(url) == bytes:
            url = url.decode()
        return {prop.split('=')[0]: prop.split('=')[1] for prop in url.split('&')}

    def decrypt_profile(self, profile):
        return self.parse_profile(self.decrypt(profile))

    def profile_for(self, addr):
        if type(addr) == str:
            addr = addr.encode()
        assert (b'&' not in addr and b'=' not in addr), "Not allowed"
        profile = b'email=' + addr + b'&uid=10&role=user'
        return self.encrypt(profile)

def main():
    import numpy as np
    from c9 import pad_pkcs7, ecb_cipher
    from c12 import find_bsz_by_len
    
    # We don't know the key, block size or encryption function, all we know is
    # the profile_for function prepends 'email=' and appends '&uid=10&role=user'
    # to the user input, and we know the output of profile_for for a given input.
    prf = profile_manager()

    # Set address length such that 'user' is at the start of a new  block so we
    # can cut off the first part, which ends with '&role='.
    bsz = find_bsz_by_len(prf.profile_for)
    pre_len = len('email=')
    post_len = len('&uid=10&role=')
    addr_len = len(pad_pkcs7((pre_len + post_len) * b'X', bsz)) - pre_len - post_len
    part1 = prf.profile_for(addr_len * b'X')[:-bsz]

    # Generate address so that 'admin' is at the start of the 2nd block so we
    # can paste it after the first part. Make sure the rest of the 2nd block is
    # padded so it is a legitimate "last" block.
    addr_len = bsz - pre_len
    addr = addr_len * b'X' + pad_pkcs7(b'admin', bsz)
    part2 = prf.profile_for(addr)[(pre_len+addr_len):(pre_len+addr_len+bsz)]

    # Paste two parts together and decrypt profile.
    ciphertext = part1 + part2
    print(prf.decrypt_profile(ciphertext))
