import numpy as np
from c10 import cbc_cipher

class random_cipher(cbc_cipher):
    def __init__(self, key, iv):
        super().__init__(key, iv)
        with open('c17data') as f:
            self.strings = f.read().split('\n')[:-1]

    def encrypt_string(self):
        string = self.strings[np.random.randint(len(self.strings))]
        return self.encrypt(string)

    def decrypt_string(self, data):
        string = self.decrypt(string)
        return string != None
