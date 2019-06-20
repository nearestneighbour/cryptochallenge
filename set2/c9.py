from Crypto.Cipher import AES

def pad_bytes(msg, bsz):
    if type(msg) == str:
        msg = bytes([ord(i) for i in msg])

    npad = bsz - (len(msg) % bsz)
    for i in range(npad):
        msg += bytes([npad])
    return msg

def unpad_bytes(msg):
    return msg[:-msg[-1]]

# Updated version of the functions from challenge 7, convenient for future challenges
def encrypt_ecb(data, key):
    cph = AES.new(key, AES.MODE_ECB)
    return cph.encrypt(pad_bytes(data, len(key)))

def decrypt_ecb(data, key):
    cph = AES.new(key, AES.MODE_EDB)
    return unpad_bytes(cph.decrypt(data))

if __name__ == '__main__':
    msg = 'YELLOW SUBMARINE'
    print(pad_bytes(msg, 20))
