import numpy as np

p = 37
g = 5
a = np.random.randint(37)
A = (g**a) % p
b = np.random.randint(37)
B = (g**a) % p
s = (B**a) % p

# From https://en.wikipedia.org/wiki/Modular_exponentiation
def modexp(b, e, m):
    c = 1
    for i in range(1, e+1):
        c = (c*b) % m
    return c

def get_session_key(p, g):
    A = modexp(g, np.random.randint(p), p)
    B = modexp(g, np.random.randint(p), p)
    return modexp(A, b, p)
