# Padding according to https://tools.ietf.org/html/rfc2313 section 8.1
def pad_pkcs15(msg, k=1024):
    n_ff = (k/8) - 3 - len(msg)
    return b'\x00\x01' + n_ff * b'\xff' + b'\x00' + msg
