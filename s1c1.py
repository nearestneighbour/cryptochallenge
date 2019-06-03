from base64 import b64encode

def hex2b64(h):
    """
    Bit of a cheat since it uses b64encode
    """
    
    if type(h) == int:
        h = hex(h)
    return b64encode(bytes.fromhex(h))
