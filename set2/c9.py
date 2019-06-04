def pad_bytes(msg, bsz):
    if type(msg) == str:
        msg = bytes([ord(i) for i in msg])

    npad = bsz - (len(msg) % bsz)
    for i in range(npad):
        msg += bytes([npad])
    return msg

msg = 'YELLOW SUBMARINE'
result = pad_bytes(msg, 20)
