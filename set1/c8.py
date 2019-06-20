def get_repetitions(data, bsz):
    # Use this to detect ECB encrypted data
    blocks = [data[i:i+bsz] for i in range(0,len(data),bsz)]
    reps = len(blocks)-len(set(blocks))
    return reps

def main():
    import numpy as np
    with open('set1/c8data') as f:
        data = f.readlines()
        data = [bytes.fromhex(d.strip()) for d in data]

    repetitions = np.zeros((len(data)))
    for i in range(len(data)):
        repetitions[i] = get_repetitions(data[i], 16)
    print(data[np.argmax(repetitions)].hex())
