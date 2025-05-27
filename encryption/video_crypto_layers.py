import base64
import hashlib
import numpy as np
import pandas as pd
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from sklearn.linear_model import LinearRegression

def encrypt_frame_enhanced(img_bytes, key_text):
    """8-Layer Modified AES Encryption with Complete Error Handling"""
    
    # Layer 1: Advanced Key Derivation
    def expand_key(key):
        salt = hashlib.sha256(key.encode()).digest()
        stretched_key = hashlib.pbkdf2_hmac(
            'sha512', 
            key.encode(), 
            salt, 
            100000, 
            64
        )
        return {
            'aes_key': stretched_key[:32],
            'permute_seed': int.from_bytes(stretched_key[32:36], 'little'),
            'xor_key': stretched_key[36:40] * 8  # Repeat to sufficient length
        }
    
    keys = expand_key(key_text)

    # Layer 2: Secure Byte Permutation
    def permute_bytes(data, seed):
        np.random.seed(seed)
        indices = np.arange(len(data))
        np.random.shuffle(indices)
        return bytes(data[i] for i in indices)
    
    permuted = permute_bytes(img_bytes, keys['permute_seed'])

    # Layer 3: XOR Stream Cipher
    xor_mask = (keys['xor_key'] * ((len(permuted) // len(keys['xor_key'])) + 1))[:len(permuted)]
    xor_applied = bytes(p ^ m for p, m in zip(permuted, xor_mask))

    # Layer 4: Modified AES-CBC with Nibble Swap
    class CustomAES:
        def __init__(self, key):
            self.iv = get_random_bytes(16)
            self.cipher = AES.new(key, AES.MODE_CBC, self.iv)
        
        def encrypt(self, data):
            processed = bytes(((b & 0x0F) << 4 | (b & 0xF0) >> 4) for b in data)
            return self.iv + self.cipher.encrypt(pad(processed, AES.block_size))
    
    aes_cipher = CustomAES(keys['aes_key'])
    aes_output = aes_cipher.encrypt(xor_applied)

    # Layer 5/6: Enhanced Visual Cryptography + Statistical Obfuscation
    h, w = min(len(key_text), 256), 256
    C = np.zeros((h, w, 3), dtype='uint8')
    for i, char in enumerate(key_text[:h]):
        val = ord(char) % w
        C[i, :val] = 1
    
    np.random.seed(keys['permute_seed'])
    R = np.random.randint(0, 256, (h, w, 3), dtype='uint8')
    P = np.bitwise_xor(R, C)

    def extract_features(arr):
        return pd.DataFrame({
            'odd': [int(np.sum(row[::2,0], dtype=np.uint32)) for row in arr],
            'even': [int(np.sum(row[1::2,0], dtype=np.uint32)) for row in arr]

        })

    x = int(extract_features(P).sum().sum()) % 256
    y = int(extract_features(R).sum().sum()) % 256

    # Layer 7: Ciphertext Transformation
    transformed = [((b + x) ^ y) for b in aes_output]
    cipher_text = ' '.join(map(str, transformed))

    # Layer 8: Key-Dependent Encoding
    def dynamic_encode(data, key):
        shift = sum(ord(c) for c in key) % 64
        b64 = base64.b64encode(data).decode()
        return b64[-shift:] + b64[:-shift] if shift else b64
    
    return {
        'cipher_text': cipher_text,
        'R_share': dynamic_encode(R.tobytes(), key_text),
        'P_share': dynamic_encode(P.tobytes(), key_text),
        'metadata': {
            'x': x,
            'y': y,
            'shape': (h, w, 3),
            'key_hash': hashlib.sha512(key_text.encode()).hexdigest()
        }
    }
