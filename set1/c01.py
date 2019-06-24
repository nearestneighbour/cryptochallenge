from base64 import b64encode

# Bit of a cheat since it uses b64encode
def hex2b64(h):
    if type(h) == int:
        h = hex(h)
    return b64encode(bytes.fromhex(h))

def main():
    h = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    print(hex2b64(h))
