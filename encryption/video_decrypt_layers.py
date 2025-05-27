import base64
import hashlib
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import pandas as pd

def decrypt_frame_enhanced(encrypted_data, key_text):
    try:
        keys = expand_key(key_text)

        # Layer 8: Key-Dependent Decoding
        def dynamic_decode(data, key):
            shift = sum(ord(c) for c in key) % 64
            if shift == 0:
                return base64.b64decode(data)
            return base64.b64decode(data[shift:] + data[:shift])

        shape = encrypted_data['metadata']['shape']
        R = np.frombuffer(
            dynamic_decode(encrypted_data['R_share'], key_text),
            dtype='uint8'
        ).reshape(shape)
        P = np.frombuffer(
            dynamic_decode(encrypted_data['P_share'], key_text),
            dtype='uint8'
        ).reshape(shape)

        # Layer 7: Ciphertext Restoration
        x = encrypted_data['metadata']['x']
        y = encrypted_data['metadata']['y']
        cipher_bytes = bytes([((int(b) ^ y) - x) % 256 
                              for b in encrypted_data['cipher_text'].split()])

        # Layer 6/5: Skip (visual cryptography not reversible without loss)

        # Layer 4: Modified AES decryption
        class CustomAES:
            def __init__(self, key, iv):
                self.cipher = AES.new(key, AES.MODE_CBC, iv)

            def decrypt(self, data):
                decrypted = unpad(self.cipher.decrypt(data), AES.block_size)
                return bytes(((b & 0x0F) << 4 | (b & 0xF0) >> 4) for b in decrypted)

        iv = cipher_bytes[:16]
        ciphertext = cipher_bytes[16:]
        aes_cipher = CustomAES(keys['aes_key'], iv)
        xor_reversed = aes_cipher.decrypt(ciphertext)

        # Layer 3: XOR Unmasking
        xor_mask = (keys['xor_key'] * ((len(xor_reversed) // len(keys['xor_key'])) + 1))[:len(xor_reversed)]
        perm_reversed = bytes(x ^ m for x, m in zip(xor_reversed, xor_mask))

        # Layer 2: Reverse Permutation
        def reverse_permute(data, seed):
            np.random.seed(seed)
            indices = np.arange(len(data))
            np.random.shuffle(indices)
            inverse = np.empty_like(indices)
            inverse[indices] = np.arange(len(data))
            return bytes(data[i] for i in inverse)

        return reverse_permute(perm_reversed, keys['permute_seed'])

    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def expand_key(key):
    salt = hashlib.sha256(key.encode()).digest()
    stretched_key = hashlib.pbkdf2_hmac('sha512', key.encode(), salt, 100000, 64)
    return {
        'aes_key': stretched_key[:32],
        'permute_seed': int.from_bytes(stretched_key[32:36], 'little'),
        'xor_key': stretched_key[36:40] * 8
    }
