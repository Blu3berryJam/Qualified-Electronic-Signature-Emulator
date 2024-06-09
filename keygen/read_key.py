import configparser
import hashlib
import os
from tkinter import filedialog

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from config_reader import load_config

ENCRYPT_ALGORITHM, KEY_SIZE, CIPHER_MODE, IV_SIZE = load_config()

def decrypt_key(encrypted_key, iv, pin):
    hashed_pin = hashlib.sha256(pin.encode()).digest()
    cipher = Cipher(ENCRYPT_ALGORITHM(hashed_pin), CIPHER_MODE(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_key = decryptor.update(encrypted_key) + decryptor.finalize()
    private_key = serialization.load_pem_private_key(
        decrypted_key,
        password=None,
        backend=default_backend()
    )
    return private_key
def read_and_decrypt_key():
    encrypted_key, iv = read_private()
    pin = input("Wprowadź swój PIN: ")
    private_key = decrypt_key(encrypted_key, iv, pin)
    print("Klucz prywatny został odszyfrowany.")
    return private_key
def read_public():
    file_path = filedialog.askopenfilename(title="Wybierz plik klucza publicznego")
    with open(file_path, "rb") as f:
        pk = load_pem_public_key(f.read(), backend=default_backend())
    print("Wybrano plik:", file_path)
    return pk
# klucz jest oczywiście wciąż zaszyfrowany ale można tak odczytać zaszyfrowany klucza i iv z pliku, żeby potem go zdekryptować
def read_private():
    file_path = filedialog.askopenfilename(title="Wybierz plik klucza prywatnego")
    with open(file_path, "rb") as f:
        file_size = os.path.getsize(file_path)
        epk = f.read(file_size - IV_SIZE)
        f.seek(-IV_SIZE, os.SEEK_END)
        iv = f.read(IV_SIZE)
    print("Wybrano plik:", file_path)
    return epk, iv
