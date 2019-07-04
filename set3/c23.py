def num_to_bits(num):
    bits = 32 * [False]
    for i in range(32):
        if num // (2**(31-i)) > 0:
            bits[i] = True
            num -= 2**(31-i)
    return bits

def bits_to_num(bits):
    num = 0
    for i in range(32):
        num += 2**(31-i) if bits[i] else 0
    return num

def untemper_right_shift(y, shift, m=None):
    yb = num_to_bits(y)
    m = num_to_bits(m) if m else 32 * [True]
    xb = 32 * [False]
    xb[:shift] = yb[:shift]
    for i in range(shift, 32):
        if m[i]:
            xb[i] = yb[i] ^ xb[i-shift]
        else:
            xb[i] = yb[i]
    return bits_to_num(xb)

def untemper_left_shift(y, shift, m=None):
    yb = num_to_bits(y)
    m = num_to_bits(m) if m else 32 * [True]
    xb = 32 * [False]
    xb[-shift:] = yb[-shift:]
    for i in range(31-shift, -1, -1):
        if m[i]:
            xb[i] = yb[i] ^ xb[i+shift]
        else:
            xb[i] = yb[i]
    return bits_to_num(xb)

def untemper_mt19937(y):
    y = untemper_right_shift(y, 18)
    y = untemper_left_shift(y, 15, 0xEFC60000)
    y = untemper_left_shift(y, 7, 0x9D2C5680)
    state = untemper_right_shift(y, 11, 0xFFFFFFFF)
    return state

def main():
    from c21 import mt19937_rng
    # Create RNG with a seed
    rng = mt19937_rng(5489)
    # Record 624 outputs
    output = [rng.rand() for i in range(624)]
    # Reconstruct RNG internal state by untempering outputs
    state = [untemper_mt19937(y) for y in output]
    # Create 'blanc' RNG and copy state into it
    copy_rng = mt19937_rng(0)
    copy_rng.mt = state
    # Compare RNG output with output of reconstructed RNG
    for i in range(10):
        print(rng.rand(), copy_rng.rand())
