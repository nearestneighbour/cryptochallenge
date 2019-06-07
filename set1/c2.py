def fixed_xor(s1,s2):
    if type(s1) == str:
        s1 = int(s1, 16)
    if type(s2) == str:
        s2 = int(s2, 16)
    return hex(s1 ^ s2)

if __name__ == '__main__':
    s1 = '1c0111001f010100061a024b53535009181c'
    s2 = '686974207468652062756c6c277320657965'
    print(fixed_xor(s1,s2))
