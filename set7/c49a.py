import numpy as np

from c10 import cbc_cipher

class server(cbc_cipher):
    def __init__(self, key):
        super().__init__(key)

    def verify_tx(self, msg, iv, mac):
        mac1 = self.encrypt_cbc(msg, self.key, iv)[-16:]
        sender, to, amount = msg.split('&')
        sender = sender.split('=')[1]
        to = to.split('=')[1]
        amount = amount.split('=')[1]
        if mac != mac1:
            print("Invalid MAC")
        else:
            print('Success - from:{}, to:{}, amount:{}'.format(sender, to, amount))

class client(cbc_cipher):
    def __init__(self, key):
        super().__init__(key)

    def send_tx(self, sender, to, amount):
        # Attacker has no control over target account
        assert sender != 'target', "Unauthorized transaction!"
        iv = np.random.bytes(16)
        msg = ('from=' + sender + '&to=' + to + '&amount=' + str(amount))
        mac = self.encrypt_cbc(msg, self.key, iv)[-16:]
        return msg, iv, mac

KEY = np.random.bytes(16)
c = client(KEY)
s = server(KEY)

def forge_tx(target, to, amount):
    assert len(target) < 12, "Sender name too long"
    # Intercept tx so we can edit the sender (sender should be same length as our target)
    msg, iv, mac = c.send_tx('X' * len(target), to, amount)
    forged_msg = 'from=' + target + msg[len(target)+5:]
    # Forge IV to control first block of message using the rule:
    # msg XOR iv = forged_msg XOR forged_iv -> forged_iv = msg XOR iv XOR forged_msg
    forged_iv = bytes([a^b^c for a,b,c in zip(msg.encode(), iv, forged_msg.encode())])
    # Server verifies transaction
    s.verify_tx(forged_msg, forged_iv, mac)
