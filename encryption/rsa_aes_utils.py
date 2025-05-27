from Crypto.PublicKey import RSA
import os
def generate_random_aes_key():
    return os.urandom(32)  # 256-bit AES key

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key
