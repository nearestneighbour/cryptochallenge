import numpy as np

# Implementation of the Mersenne Twister RNG based on pseudocode from:
# https://en.wikipedia.org/wiki/Mersenne_Twister

# Parameters according to MT19937-64:
w = 64 # word size (in bits)
n = 312 # degree of recurrence
m = 156 # middle word, offset used in recurrence relation defining x. 1 ≤ m < n
r = 31 # sep. point of a word, or #bits of the lower bitmask. 0 ≤ r ≤ w - 1
a = 0xB5026F5AA96619E9 # coefficients of the rational normal form twist matrix
# Additional parameters for tempering bitmasks/bit shifts:
u = 29
d = 0x5555555555555555
s = 17
b = 0x71D67FFFEDA60000
t = 37
c = 0xFFF7EEE000000000
l = 43

def bitwise_not(n):
    return (1 << w) - 1 - n

def low_bits(n):
    return n - ((n >> w) << w)

mt = np.zeros(n, dtype='int64') # to store generator state
lower_mask = (1 << r) - 1
tmp = bitwise_not(lower_mask, 64)
upper_mask = low_bits(tmp, w)

def seed_mt(seed):
    index = n
    mt[0] = seed
    for i in range(n-1):
        tmp = mt[i] ^ (mt[i] >> (w-2))
        mt[i+1] = lowest_bits(f*tmp + i-1) # what is f???

def extract_number()
