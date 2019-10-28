from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Crypto import Random
from Crypto.Cipher import AES

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
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:])).decode('utf8')

if __name__ == '__main__':
    cookie = 'Piw96Gvx5Jz01V7iuMXSwWDkcRYB1vIVzj5atcBhkuqsQTkDgjoYYj7UWvAR9L6F/v0rCYLU5N1tq6zAU7XnObn1+2AEjRv8kb1PD9onqqA='

    iv, cipher = decode_text(cookie)

    print('IV', iv.hex())
    print('Cipher', cipher.hex())
