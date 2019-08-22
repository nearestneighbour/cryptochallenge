from c47 import padding_oracle, bleichenbacher

def main():
    p = padding_oracle(k=768)
    msg = b'kick it, CC and make this message a bit longer'
    plaintext = p.pad_pkcs1(msg, btype=2)
    ciphertext = p.encrypt(plaintext)

    pt = bleichenbacher(c0=ciphertext, oracle=p.padded, pub=p.publickey())
    if pt == plaintext:
        print('Found plaintext!')
    else:
        print(pt)
