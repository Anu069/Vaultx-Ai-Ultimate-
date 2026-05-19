from cryptography.fernet import Fernet
from flask import current_app
import base64
import os
import hashlib

def get_cipher():
    key = current_app.config['ENCRYPTION_KEY']
    if isinstance(key, str):
        key = key.encode()
    # Ensure valid Fernet key
    try:
        return Fernet(key)
    except Exception:
        # Generate a proper key from the provided key
        derived = hashlib.sha256(key).digest()
        proper_key = base64.urlsafe_b64encode(derived)
        return Fernet(proper_key)

def encrypt_data(plaintext: str) -> str:
    if not plaintext:
        return ''
    cipher = get_cipher()
    return cipher.encrypt(plaintext.encode()).decode()

def decrypt_data(ciphertext: str) -> str:
    if not ciphertext:
        return ''
    try:
        cipher = get_cipher()
        return cipher.decrypt(ciphertext.encode()).decode()
    except Exception:
        return '[Decryption Error]'

def encrypt_file(file_data: bytes) -> bytes:
    cipher = get_cipher()
    return cipher.encrypt(file_data)

def decrypt_file(encrypted_data: bytes) -> bytes:
    cipher = get_cipher()
    return cipher.decrypt(encrypted_data)

def generate_backup_key(password: str, salt: bytes = None) -> tuple:
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    fernet_key = base64.urlsafe_b64encode(key)
    return Fernet(fernet_key), salt

def create_encrypted_backup(data: str, password: str) -> bytes:
    cipher, salt = generate_backup_key(password)
    encrypted = cipher.encrypt(data.encode())
    return salt + encrypted

def restore_encrypted_backup(backup_data: bytes, password: str) -> str:
    salt = backup_data[:16]
    encrypted = backup_data[16:]
    cipher, _ = generate_backup_key(password, salt)
    return cipher.decrypt(encrypted).decode()
