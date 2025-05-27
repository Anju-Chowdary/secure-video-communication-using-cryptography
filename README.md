# Secure Video Communication Platform with Advanced Encryption and MongoDB Backend

## Project Overview  
This project is a secure video communication platform built with Flask and MongoDB. It enables encrypted video exchange with strong layered encryption and secure key management.

## Key Features  
- User signup with Argon2 password hashing.  
- RSA key pair generation per user for asymmetric encryption; public key stored in MongoDB (also hill-cipher encrypted), private key provided to user as PEM file (vault private key).  
- ECDSA keys for digital signatures and vault authentication.  
- Video request/response system stored and managed in MongoDB collections (`video_requests`, `video_responses`, etc.).  
- Videos processed frame-by-frame and encrypted with a custom 8-layer AES-based scheme.  
- Symmetric keys for video frames are encrypted with recipient’s RSA public key.  
- Vault system for secure private key authentication and video decryption.  
- Videos decrypted by recipients using their private keys and reassembled for playback.

## Technologies Used  
- Flask (Python) backend  
- MongoDB (via `pymongo`) for user data, requests, encrypted videos, and logs  
- Cryptography libraries (`cryptography`, Argon2, PyCryptodome)  
- OpenCV and PIL for video processing  
- Custom layered encryption combining AES, XOR, permutations, visual cryptography, and statistical obfuscation  

## MongoDB Collections  
- `users`: User credentials, hashed passwords, RSA/ECDSA keys, vault data  
- `video_requests`: Records video requests with statuses (`pending`, `responding`, `completed`)  
- `video_responses`: Metadata about encrypted videos, including encrypted symmetric keys  
- `video_frames`: Stores individual encrypted frames linked to videos  
- `video_logs`: Event and action logs  

## Encryption Layers Summary  
1. Key derivation and salt generation  
2. Secure byte permutation of video frames  
3. XOR stream cipher obfuscation  
4. Modified AES-CBC with nibble swapping  
5. Visual cryptography and bitwise operations  
6. Statistical obfuscation of frame data  
7. Ciphertext byte transformations  
8. Key-dependent base64 encoding  

## How to Run  
- Install dependencies (`flask`, `pymongo`, `cryptography`, `argon2-cffi`, `opencv-python`, `pillow`, etc.)  
- Setup MongoDB locally (default URI: `mongodb://localhost:27017/`)  
- Run Flask app (`python app.py`)  
- Access via `http://127.0.0.1:5000/`  

## Important  
- Users must securely store their private key PEM file to decrypt videos.  
- MongoDB is central for storing all user, request, and encrypted video data.  
- The custom encryption scheme ensures multi-layered security, protecting video frames during storage and transmission.
