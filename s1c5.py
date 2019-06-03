def repeat_xor(msg,key):
    """
    Multi-byte XOR encrypt a message
    """

    if type(msg) == str:
        msg = msg.encode('utf-8')
    if type(key) == str:
        key = key.encode('utf-8')
    return bytes([msg[i]^key[i%len(key)] for i in range(len(msg))])
