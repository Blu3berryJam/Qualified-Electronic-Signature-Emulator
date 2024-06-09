import base64
import configparser
import os
import hashlib
from datetime import datetime
from tkinter import filedialog

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import lxml.etree as ET

import read_key
from config_reader import load_config
from keygen import verify

ENCRYPT_ALGORITHM, KEY_SIZE, CIPHER_MODE, IV_SIZE = load_config()


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
    file_path = filedialog.asksaveasfilename(defaultextension=".enc", title="Wybierz lokalizacje do zapisania klucza prywatnego")
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
    print(private_key)
    pin = input("Enter your PIN: ")
    encrypted_key, iv = encrypt_key(private_key, pin)

    save_keys(encrypted_key, public_key, iv)


def en():
    public_key = load_pem_public_key(read_key.read_public(), backend=default_backend())
    en = public_key.encrypt(
        b"dupa",
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return en


def dec(private_key, message_encrypted):
    try:
        message_decrypted = private_key.decrypt(
            message_encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return f"Decrypted Message: {message_decrypted}"
    except ValueError:
        return "Failed to Decrypt"


def sign_document(document_path, private_key):
    with open(document_path, 'rb') as f:
        document_data = f.read()
    document_hash = hashlib.sha256(document_data).digest()
    signature = private_key.sign(
        document_hash,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature, document_hash


def generate_xades_signature(document_path, signature, document_hash):
    document_size = os.path.getsize(document_path)
    document_extension = os.path.splitext(document_path)[1]
    document_modification_date = datetime.fromtimestamp(os.path.getmtime(document_path)).isoformat()
    signature_timestamp = datetime.now().isoformat()

    root = ET.Element("XAdESSignature")
    doc_info = ET.SubElement(root, "DocumentInfo")
    ET.SubElement(doc_info, "Size").text = str(document_size)
    ET.SubElement(doc_info, "Extension").text = document_extension
    ET.SubElement(doc_info, "ModificationDate").text = document_modification_date

    ET.SubElement(root, "DocumentHash").text = base64.b64encode(document_hash).decode()
    ET.SubElement(root, "Signature").text = base64.b64encode(signature).decode()
    ET.SubElement(root, "Timestamp").text = signature_timestamp

    tree = ET.ElementTree(root)
    xml_file_path = document_path + ".xades.xml"
    tree.write(xml_file_path, pretty_print=True, xml_declaration=True, encoding="UTF-8")
    print(f"Podpisano plik XML i zapisano jako {xml_file_path}")


if __name__ == '__main__':
    keygen()

    dec_private_key = read_key.read_and_decrypt_key()
    document_path = filedialog.askopenfilename(title="Wybierz dokument do podpisania")
    if not document_path:
        print("Nie wybrano dokumentu do podpisania.")

    signature, document_hash = sign_document(document_path, dec_private_key)
    generate_xades_signature(document_path, signature, document_hash)

    document_path = filedialog.askopenfilename(title="Wybierz dokument do weryfikacji")
    if not document_path:
        print("Nie wybrano dokumentu do weryfikacji.")

    # Wybierz plik XML z podpisem
    xml_path = filedialog.askopenfilename(title="Wybierz plik XML z podpisem")
    if not xml_path:
        print("Nie wybrano pliku XML z podpisem.")

    # Wybierz plik klucza publicznego
    public_key_path = filedialog.askopenfilename(title="Wybierz plik klucza publicznego")
    if not public_key_path:
        print("Nie wybrano pliku klucza publicznego.")

    verify.verify_signature(document_path, xml_path)
