from c28 import sha1

class sha1_append_msg(sha1):
    def __init__(self, state, prep_len):
        self.h = state
        self.pl = prep_len

    def pad_msg(self, msg): # Overwrite sha1's pad_msg function
        ml = ((len(msg) + self.pl) * 8).to_bytes(8, 'big')
        msg += bytes([128])
        while (len(msg) % 64) < 56:
            msg += b'\x00'
        return msg + ml

def main():
    import numpy as np
    # We have MAC(key || msg), and we want to get MAC(key || msg || our_msg) without
    # knowing the key (only it's size).
    key = np.random.bytes(16)
    org_msg = (b'comment1=cooking%20MCs;userdata=foo;'
               b'comment2=%20like%20a%20pound%20of%20bacon')
    org_mac = sha1().auth(org_msg, key)

    # Using the sha-1 padding function, calculate the padded length of the input
    # used for the original MAC.
    prepend_len = len(sha1().pad_msg(bytes(16) + org_msg))
    # Derive the state of the sha-1 function from the MAC.
    state = [int.from_bytes(org_mac[i:i+4], 'big') for i in range(0, 20, 4)]
    # Compute new mac
    m = sha1_append_msg(state, prepend_len)
    new_mac = m.digest(b';admin=true')
    print('Our MAC: ', new_mac)
    mac = sha1().digest(sha1().pad_msg(key+org_msg)+b';admin=true')
    print('Valid MAC: ', mac)
