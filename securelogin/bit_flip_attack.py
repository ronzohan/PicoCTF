from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Crypto import Random
from Crypto.Cipher import AES

BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE).encode()
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def decode_text(enc):
    decoded_text = b64decode(enc)
    iv = decoded_text[:16]
    cipher_text = decoded_text[16:]

    return (iv, cipher_text)

def encode_cipher(iv, cipher_text):
    return b64encode(iv + cipher_text)

class AESCipher:
    """
    Usage:
        c = AESCipher('password').encrypt('message')
        m = AESCipher('password').decrypt(c)
    Tested under Python 3 and PyCrypto 2.6.1.
    """

    def __init__(self, key):
        self.key = md5(key.encode('utf8')).hexdigest()

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key.encode(), AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key.encode(), AES.MODE_CBC, iv)
        dec = cipher.decrypt(enc[16:])
        return unpad(dec).decode('utf8')

if __name__ == '__main__':
    # Expected string for this encrypted text
    # {'admin': 0, 'username': 'aaaaa', 'password': ''}
    cookie = '5B4MngDAGKfG8zoY+U2ijPWPwd0jLBO/+8jet0Txkx5N05MgZpG0m5dQ6zjlXwbTkapttxNiJSf6FqTLKFtUlrbfVtKBqZ/MPQQtHIToLf8='

    iv, cipher = decode_text(cookie)

    print('IV', iv.hex())
    print('Cipher', cipher.hex())

    # We can XOR the IV and the expected value so that it will cancel
    # out the corresponding XOR onto the decrypted text with a key.
    # With that, we can inject our own value with another XOR.
    new_iv = iv[:10] + chr(iv[10] ^ 0 ^ 1).encode() + iv[11:]
    new_enc = encode_cipher(new_iv, cipher)
    print('New encrypted text', new_enc)
    print('New encrypted text hex', new_enc.hex())





