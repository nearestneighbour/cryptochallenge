from c43 import dsa

# If g == 0, then y = 0, r = 0, and s is independent of x (but depends on k).
# However the r=0 gets caught by the error handling in both the sign() and
# verify() functions so this won't be useful for attacks.

# If g == p + 1, then y = 1 and r = 1. This case won't be caught by the sign()
# and verify() functions. Any signature with r = 1 will be accepted, not just
# the ones with (r,s) computed according to the equations in the challenge.

def main():
    d = dsa(g=dsa.p + 1)
    msg = b'Hello, world'
    if d.verify(msg, (1, 123456789)):
        print('Signature accepted')
