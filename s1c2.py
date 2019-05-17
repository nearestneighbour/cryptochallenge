def hex_xor(a, b, s=False):
    if type(a) == str:
        a = int(a,16)
    if type(b) == str:
        b = int(b,16)
    if s:
        return hex(a ^ b)
    else:
        return a ^ b
