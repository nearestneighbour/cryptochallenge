def encrypt_repeat_xor(msg,key):
    if type(msg) == str:
        msg = msg.encode()
    if type(key) == str:
        key = key.encode()
    return bytes([msg[i]^key[i%len(key)] for i in range(len(msg))])

def main():
    msg = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = 'ICE'
    print(encrypt_repeat_xor(msg, key).hex())
