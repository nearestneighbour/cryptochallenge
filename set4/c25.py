from c10 import cbc_cipher
from c18 import ctr_cipher

class ctr_cipher_edit(ctr_cipher):
    def edit(self, ct, offset, newtxt):
        pt = self.decrypt(ct)
        newpt = pt[:offset] + newtxt + pt[offset+len(newtxt):]
        return self.encrypt(newpt)

def main():
    from base64 import b64decode
    cph = ctr_cipher_edit()
    # Load data from the ECB exercise and encrypt it. For the attack we only have
    # access to the ciphertext and the edit function, not the encryption function.
    with open('set2/c10data') as f:
        data = b64decode(f.read())
        ct = cph.encrypt(cbc_cipher(b'YELLOW SUBMARINE', bytes(16)).decrypt(data))

    # Reveal keystream by replacing the entire ciphertext with 0-bytes
    keystream = cph.edit(ct, 0, bytes(len(ct)))
    # XOR ciphertext against keystream to reveal plaintext
    print(bytes([a^b for a,b in zip(ct, keystream)]))
