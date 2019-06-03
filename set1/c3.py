import numpy as np

freqs_EN = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }

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
