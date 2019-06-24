import numpy as np
from c03 import decrypt_single_xor, score_text_EN

def main():
    with open('set1/c04data') as f:
        data = f.readlines()
        data = [d.strip() for d in data]

    msg = []
    scores = np.zeros((len(data)))
    for i in range(len(data)):
        m, _ = decrypt_single_xor(data[i])
        msg += [m]
        scores[i] = score_text_EN(m)

    print(msg[np.argmax(scores)])
