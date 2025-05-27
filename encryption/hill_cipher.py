import numpy as np

def text_to_nums(text):
    return [(ord(c.upper()) - ord('A')) % 26 for c in text]

def nums_to_text(nums):
    return ''.join([chr((num % 26) + ord('A')) for num in nums])

def create_hill_key_matrix(username):
    key_str = (username.upper() * 2)[:4]  # 2x2 matrix
    key_nums = text_to_nums(key_str)
    return np.array(key_nums).reshape(2, 2)

def hill_encrypt(text, username):
    matrix = create_hill_key_matrix(username)
    text = ''.join(c for c in text.upper() if c.isalpha())  # Remove non-letters
    if len(text) % 2 != 0:
        text += 'X'
    nums = text_to_nums(text)
    encrypted = []
    for i in range(0, len(nums), 2):
        pair = np.array(nums[i:i+2])
        result = np.dot(matrix, pair) % 26
        encrypted.extend(result)
    return nums_to_text(encrypted)

def modinv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise Exception("No modular inverse!")

def matrix_modinv(matrix):
    det = int(np.round(np.linalg.det(matrix))) % 26
    inv_det = modinv(det, 26)
    adj = np.round(det * np.linalg.inv(matrix)).astype(int) % 26
    return (inv_det * adj) % 26

def hill_decrypt(ciphertext, username):
    matrix = create_hill_key_matrix(username)
    inv_matrix = matrix_modinv(matrix)
    nums = text_to_nums(ciphertext)
    decrypted = []
    for i in range(0, len(nums), 2):
        pair = np.array(nums[i:i+2])
        result = np.dot(inv_matrix, pair) % 26
        decrypted.extend(result)
    return nums_to_text(decrypted)
