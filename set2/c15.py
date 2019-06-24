def unpad_pkcs7(data):
    npad = data[-1]
    for i in data[-npad:]:
        if i != npad:
            return None
    return data[:-npad]

def main():
    print(unpad_pkcs7(b'ICE ICE BABY\x04\x04\x04\x04'))
