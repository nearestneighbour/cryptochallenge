from c10 import cbc_cipher
from c15 import unpad_pkcs7

class admin_cipher(cbc_cipher):
    def encrypt(self, data):
        if type(data) == str:
            data = data.encode()
        assert (b';' not in data and b'=' not in data), "Not allowed"

        pre = b'comment1=cooking%20MCs;userdata='
        post = b';comment2=%20like%20a%20pound%20of%20bacon'
        return super().encrypt(pre + data + post)

    def check_admin(self, data):
        data = unpad_pkcs7(self.decrypt(data)).decode()
        datadict = {prop.split('=')[0]: prop.split('=')[1] for prop in data.split(';')}
        return datadict.pop('admin', False)
