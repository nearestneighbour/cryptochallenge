from c10 import cbc_cipher

class admin_cipher(cbc_cipher):
    def encrypt_data(self, data):
        if type(data) == str:
            data = data.encode()
        assert (b';' not in data and b'=' not in data), "Not allowed"
        pre = b'comment1=cooking%20MCs;userdata='
        post = b';comment2=%20like%20a%20pound%20of%20bacon'
        return self.encrypt(pre + data + post)

    def decrypt_data(self, data):
        data = ''.join([chr(i) for i in self.decrypt(data)])
        datadict = {prop.split('=')[0]: prop.split('=')[1] for prop in data.split(';')}

        #return datadict.pop('admin', False)
        return datadict # Nicer than just returning True/False

# To do: generalize byte flipping method into a function

def main():
    cph = admin_cipher()
    # Calculate input prepend length needed for our stuff to start at a new block
    prep_len = len('comment1=cooking%20MCs;userdata=')
    input_prep_len = (16 - (prep_len % 16)) % 16
    input_prep = input_prep_len * b'X'
    # The \x00's will be flipped to become ; and = resp.
    input = input_prep + b'XXXXX\x00admin\x00true'
    # Positions of the semicolon and equal symbol
    sc_idx = prep_len + input_prep_len + 5
    eq_idx = prep_len + input_prep_len + 11
    # Flipping a byte in block i will scramble block i and flip a byte in block i+1,
    # so in order to not scramble the prepended data we add another full block
    # before the input. (Now the block that will be scrambled is just userdata)
    output = cph.encrypt_data(16 * b'X' + input)
    # Flip relevant bytes
    sc_flip = bytes([output[sc_idx] ^ ord(';')])
    eq_flip = bytes([output[eq_idx] ^ ord('=')])
    output = output[:sc_idx] + sc_flip + output[sc_idx+1:eq_idx] + eq_flip + output[eq_idx+1:]
    print(cph.decrypt_data(output))
