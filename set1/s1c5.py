def encrypt_repeat_xor(msg,key):
    """
    Multi-byte XOR encrypt a message
    """

    if type(msg) == str:
        msg = msg.encode('utf-8')
    if type(key) == str:
        key = key.encode('utf-8')
    return bytes([msg[i]^key[i%len(key)] for i in range(len(msg))])

# I'm not sure how to deal with line endings so I store each line as a list item
msg = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key = 'ICE'
result = encrypt_repeat_xor(msg, key).hex()
