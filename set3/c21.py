# Implementation of the Mersenne Twister RNG based on pseudocode from:
# https://en.wikipedia.org/wiki/Mersenne_Twister
class mt19973_rng:
    def __init__(self, seed, **kwargs):
        # Parameters according to MT19937:
        self.w = kwargs.pop('w', 32)
        self.n = kwargs.pop('n', 624)
        self.m = kwargs.pop('m', 397)
        self.r = kwargs.pop('r', 31)
        self.a = kwargs.pop('a', 0x9908B0DF)
        self.u = kwargs.pop('u', 11)
        self.d = kwargs.pop('d', 0xFFFFFFFF)
        self.s = kwargs.pop('s', 7)
        self.b = kwargs.pop('b', 0x9D2C5680)
        self.t = kwargs.pop('t', 15)
        self.c = kwargs.pop('c', 0xEFC60000)
        self.l = kwargs.pop('l', 18)
        self.f = kwargs.pop('f', 0x6C078965)
        self.initialize(seed)

    def initialize(self, seed):
        self.mt = self.n * [0] # generator state
        self.lower = (1 << self.r) - 1
        self.upper = self.low_bits((1 << self.w) - 1 - self.lower)
        self.index = self.n
        self.mt[0] = seed
        for i in range(self.n-1):
            tmp = self.mt[i] ^ (self.mt[i] >> (self.w-2))
            self.mt[i+1] = self.low_bits(self.f*tmp + i + 1)

    def rand(self):
        if self.index == self.n:
            self.twist()
        y = self.mt[self.index]
        y ^= (y >> self.u) & self.d
        y ^= (y << self.s) & self.b
        y ^= (y << self.t) & self.c
        y ^= y >> self.l
        self.index += 1
        return self.low_bits(y)

    def twist(self):
        for i in range(self.n-1):
            x = (self.mt[i] & self.upper) + (self.mt[i+1] & self.lower)
            x = (x >> 1) if (x % 2) == 0 else (x >> 1) ^ self.a
            self.mt[i] = self.mt[(i+self.m) % self.n] ^ x
        self.index = 0

    def low_bits(self, i):
        return i & (2**self.w-1)

class mt19973_64_rng(mt19973_rng):
    def __init__(self, seed, **kwargs):
        # Parameters according to MT19937-64:
        self.w = kwargs.pop('w', 64)
        self.n = kwargs.pop('n', 312)
        self.m = kwargs.pop('m', 156)
        self.r = kwargs.pop('r', 31)
        self.a = kwargs.pop('a', 0xB5026F5AA96619E9)
        self.u = kwargs.pop('u', 29)
        self.d = kwargs.pop('d', 0x5555555555555555)
        self.s = kwargs.pop('s', 17)
        self.b = kwargs.pop('b', 0x71D67FFFEDA60000)
        self.t = kwargs.pop('t', 37)
        self.c = kwargs.pop('c', 0xFFF7EEE000000000)
        self.l = kwargs.pop('l', 43)
        self.f = kwargs.pop('f', 6364136223846793005)
        self.initialize(seed)

def main():
    rng = mt19973_rng(seed=5489)
    for i in range(10):
        print(rng.rand())
