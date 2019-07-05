from c18 import ctr_cipher

class admin_cipher(ctr_cipher):
    def encrypt_data(self, data):
        assert (b';' not in data and b'=' not in data), "Not allowed"
        pre = b'comment1=cooking%20MCs;userdata='
        post = b';comment2=%20like%20a%20pound%20of%20bacon'
        return self.encrypt(pre + data + post)

    def decrypt_data(self, data):
        data = ''.join([chr(i) for i in self.decrypt(data)])
        datadict = {prop.split('=')[0]: prop.split('=')[1] for prop in data.split(';')}
        return datadict

def main():
    cph = admin_cipher()
    # We want to change the input to '4;admin=true'
    newpt = b'4;admin=true'
    nbytes = len(newpt)
    prep_len = len('comment1=cooking%20MCs;userdata=')
    # Input 0-bytes to reveal keystream
    ct = cph.encrypt_data(bytes(nbytes))
    keystream = ct[prep_len:prep_len+nbytes]
    newct = bytes([a^b for a,b in zip(newpt,keystream)])
    ct = ct[:prep_len] + newct + ct[prep_len+nbytes:]
    print(cph.decrypt_data(ct))
