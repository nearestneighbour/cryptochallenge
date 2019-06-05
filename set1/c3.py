import numpy as np

from character_frequencies import freqs_EN

def byte_xor(input, char):
    return bytes([byte^char for byte in input])

def score_text_EN(msg):
    return sum([freqs_EN.get(chr(c),0) for c in msg.lower()])

def decrypt_single_xor(cph):
    """
    Given a message encrypted with single-byte XOR,
    find the key and decrypt the message.
    cph: hex string (or int)
    """

    if type(cph) == str:
        cph = bytes.fromhex(cph)

    scores = np.zeros((256))
    for char in range(256):
        msg = byte_xor(cph, char)
        scores[char] = score_text_EN(msg)

    char = np.argmax(scores)
    msg = byte_xor(cph, char)
    return msg, char

hexstr = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
result = decrypt_single_xor(hexstr)
