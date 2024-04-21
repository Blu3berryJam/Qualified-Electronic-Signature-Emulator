import os
import hashlib
from tkinter import filedialog

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ENCRYPT_ALGORITHM = algorithms.AES
KEY_SIZE = 4096
#BLOCK_SIZE = 0
CIPHER_MODE = modes.CFB
IV_SIZE = 16


def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


def encrypt_key(private_key, pin):
    hashed_pin = hashlib.sha256(pin.encode()).digest()

    initial_vector = os.urandom(IV_SIZE)
    cipher = Cipher(ENCRYPT_ALGORITHM(hashed_pin), CIPHER_MODE(initial_vector), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )) + encryptor.finalize()

    return encrypted_key, initial_vector


def save_keys(encrypted_private_key, public_key, iv):
    file_path = filedialog.asksaveasfilename(defaultextension=".enc")
    if file_path:
        with open(file_path, "wb") as f:
            f.write(encrypted_private_key)
            f.write(iv)
        print("Private key saved to:", file_path)
    file_path = os.path.join('../key/', "public_key.pem")
    os.makedirs('../key/', exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        print("Public key saved to:", file_path)


def keygen():
    private_key, public_key = generate_rsa_keys()
    pin = input("Enter your PIN: ")
    encrypted_key, iv = encrypt_key(private_key, pin)
    save_keys(encrypted_key, public_key, iv)


if __name__ == '__main__':
    keygen()
