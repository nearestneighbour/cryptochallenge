from c06 import decrypt_repeat_xor
from c18 import ctr_cipher

def main():
    from base64 import b64decode
    cph = ctr_cipher(prefix=bytes(8), little_endian=True)
    with open('set3/c20data') as f:
        data = [b64decode(line.strip()) for line in f.readlines()]
        data = [cph.encrypt(line) for line in data]

    n = min([len(line) for line in data])
    data_trunc = [line[:n] for line in data]
    blockstring = b''.join(data_trunc)
    msg, _ = decrypt_repeat_xor(blockstring, n)
    print(msg)
