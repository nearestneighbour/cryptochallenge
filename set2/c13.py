import numpy as np
from c9 import encrypt_ecb, decrypt_ecb
from c12 import find_blocksize

def parse_profile(url):
    return {prop.split('=')[0]: prop.split('=')[1] for prop in url.split('&')}

def profile_for(email):
    assert ('&' not in email and '=' not in email), "Stupid hacker"
    profile = 'email=' + email + 'uid=10&role=user'
    return encrypt_ecb(profile.encode(), kklklm) # key is a global variable

def decrypt_profile(profile, key):
    return parse_profile(decrypt_ecb(profile, key))  # key is a global variable

if __name__ == '__main__':
    # We don't know the key or the block size
    key = np.random.bytes(16)
    # We can only know the output of the profile_for function for a given input
    myprofile = profile_for('')
    bsz = find_blocksize(myprofile, profile_for)
    # Mail should be of such length that 'user' is at the start of a new block
    mail_length = (len(myprofile) - 5) % bsz
