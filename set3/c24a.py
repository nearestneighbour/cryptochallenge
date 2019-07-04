# I decided to make an "extra" challenge because 24 was a bit boring. Here we
# combine the skills of breaking cryptography and breaking a PRNG. For this
# challenge we have the MT19937 stream cipher from challenge 24, and a function
# that takes in plaintext, appends an unknown string and encrypts it. Using the
# cipher, plaintext and ciphertext, decrypt the unknown string.

from base64 import b64decode
from c23 import untemper_mt19937
from c24 import mt19937_stream

def encrypt(data):
    cph = mt19937_stream()
    unknown = b64decode('SSBjYW4gY3JlYXRlIGNoYWxsZW5nZXMgdG9v')
    return cph.encrypt(data + unknown)

def main():
    # The stream cipher should generate 624 numbers to encryp the plaintext. One
    # number is 4 bytes so our plaintext should be 624*4=2496 bytes.
    ct = encrypt(2496 * b'A')
    # Recover keystream using part of plaintext and ciphertext that is known
    keybytes = bytes([ct[i]^ord('A') for i in range(2496)])
    # Convert keystream bytes to 32-bit ints
    keyints = [int.from_bytes(keybytes[i:i+4], 'big') for i in range(0,2496,4)]
    # From the 624 ints, recover the PRNG state and create a copy
    state = [untemper_mt19937(k) for k in keyints]
    copy_cph = mt19937_stream()
    copy_cph.mt = state
    # After the 2496*b'A' string, the PRNG generates a new state using twist() to
    # encode the rest of the string (the unknown part).
    copy_cph.twist()
    print(copy_cph.encrypt(ct[2496:]))
