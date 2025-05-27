import hashlib
import os
import base64

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    pwd_salt = password.encode() + salt
    hashed = hashlib.sha256(pwd_salt).digest()
    return {
        'salt': base64.b64encode(salt).decode(),
        'hash': base64.b64encode(hashed).decode()
    }

def verify_password(stored_hash, stored_salt, input_password):
    salt = base64.b64decode(stored_salt)
    check = hash_password(input_password, salt)
    return check['hash'] == stored_hash
