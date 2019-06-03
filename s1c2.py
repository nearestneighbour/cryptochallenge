def byte_xor(input, char):
    """
    Single-byte XOR encrypt a message.
    """

    return bytes([byte^char for byte in input])
