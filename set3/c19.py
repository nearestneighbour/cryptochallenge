from c03 import decrypt_single_xor
from c18 import ctr_cipher

def main():
    from base64 import b64decode
    cph = ctr_cipher(prefix=bytes(8), little_endian=True)
    with open('set3/c19data') as f:
        data = [b64decode(line.strip()) for line in f.readlines()]
        data = [cph.encrypt(line) for line in data]

    # Since all messages have the same key, each line[i] of the lines in the data is
    # encoded with the same character key[i]. So create a block of all line[i] and
    # decrypt it using single byte XOR decryption from challenge 3. This works great
    # except for the few longest lines, because here the sample size is too low.
    m = max([len(line) for line in data])
    key = b''
    for i in range(m):
         block = b''.join([bytes([line[i]]) for line in data if len(line) > i])
         _, char = decrypt_single_xor(block)
         key += bytes([char])

    for i in range(len(data)):
        line = bytes([data[i][j]^key[j] for j in range(len(data[i]))])
        print(line)
