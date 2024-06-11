import base64
import configparser
import os
import threading

# import odfpy
from odf.opendocument import load, OpenDocumentText
from odf.text import P
import hashlib
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox
import win32api
import win32file
import time

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import lxml.etree as ET

import read_key
from config_reader import load_config

import verify

ENCRYPT_ALGORITHM, KEY_SIZE, CIPHER_MODE, IV_SIZE = load_config()
stop_thread = False


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
    file_path = filedialog.asksaveasfilename(defaultextension=".enc",
                                             title="Wybierz lokalizacje do zapisania klucza prywatnego")
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


def en(text, path):
    public_key = read_key.read_public(path)
    enc = public_key.encrypt(
        text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return enc


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
        return message_decrypted
    except ValueError:
        return "Failed to Decrypt"


def read_odt_file(file_path):
    # Load the ODT file
    doc = load(file_path)

    # Extract text content
    content = []
    for elem in doc.getElementsByType(P):
        content.append(str(elem))

    return '\n'.join(content)


def write_to_odt_file(file_path, text):
    # Create a new OpenDocument text document
    doc = OpenDocumentText()

    # Add a paragraph with the provided text
    p = P(text=text)
    doc.text.addElement(p)

    # Save the document
    doc.save(file_path)


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
    return f"Podpisano plik. Podpis zapisano jako {xml_file_path}"


def search_for_private_key(drive):
    for root, dirs, files in os.walk(drive):
        for file in files:
            if file.endswith('.enc'):
                return os.path.join(root, file)
    return None


def create_gui():
    root = tk.Tk()

    def generate_keys_gui():
        def save_keys_action():
            pin = pin_entry.get()
            private_key_path = private_key_entry.get()
            public_key_path = public_key_entry.get()
            if not pin:
                messagebox.showerror("Błąd", "PIN nie może być pusty.")
                return
            if not private_key_path or not public_key_path:
                messagebox.showerror("Błąd", "Ścieżki do plików nie mogą być puste.")
                return
            private_key, public_key = generate_rsa_keys()
            encrypted_key, iv = encrypt_key(private_key, pin)
            with open(private_key_path, "wb") as f:
                f.write(encrypted_key)
                f.write(iv)
            print("Private key saved to:", private_key_path)
            with open(public_key_path, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            print("Public key saved to:", public_key_path)
            messagebox.showinfo("Informacja", "Klucze RSA zostały wygenerowane i zapisane.")
            generate_keys_window.destroy()

        def choose_private_key_path():
            path = filedialog.asksaveasfilename(defaultextension=".enc", initialfile="private_key.enc",
                                                title="Zapisz zaszyfrowany klucz prywatny")
            if path:
                private_key_entry.delete(0, tk.END)
                private_key_entry.insert(0, path)

        def choose_public_key_path():
            path = filedialog.asksaveasfilename(defaultextension=".pem", initialfile="public_key.pem",
                                                title="Zapisz klucz publiczny")
            if path:
                public_key_entry.delete(0, tk.END)
                public_key_entry.insert(0, path)

        generate_keys_window = tk.Toplevel(root)
        generate_keys_window.title("Generowanie kluczy RSA")

        tk.Label(generate_keys_window, text="Wprowadź PIN:").grid(row=0, column=0, sticky='e')
        pin_entry = tk.Entry(generate_keys_window, show='*', width=30)
        pin_entry.grid(row=0, column=1)

        tk.Label(generate_keys_window, text="Ścieżka do klucza prywatnego:").grid(row=1, column=0, sticky='e')
        private_key_entry = tk.Entry(generate_keys_window, width=50)
        private_key_entry.grid(row=1, column=1)
        tk.Button(generate_keys_window, text="Wybierz", command=choose_private_key_path).grid(row=1, column=2)

        tk.Label(generate_keys_window, text="Ścieżka do klucza publicznego:").grid(row=2, column=0, sticky='e')
        public_key_entry = tk.Entry(generate_keys_window, width=50)
        public_key_entry.grid(row=2, column=1)
        tk.Button(generate_keys_window, text="Wybierz", command=choose_public_key_path).grid(row=2, column=2)

        tk.Button(generate_keys_window, text="Zapisz klucze", command=save_keys_action).grid(row=3, columnspan=3,
                                                                                             pady=10)

    def sign_document_gui():

        def usb_monitor(callback):

            global stop_thread
            drive_list = set()
            while not stop_thread:
                drives = win32api.GetLogicalDriveStrings().split('\000')[:-1]
                new_drives = set(drives) - drive_list
                for drive in new_drives:
                    if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                        time.sleep(3)
                        private_key_path = search_for_private_key(drive)
                        if private_key_path:
                            callback(private_key_path)
                            stop_thread = True
                drive_list = set(drives)
                time.sleep(1)

        def sign_document_action():
            document_path = document_entry.get()
            global stop_thread
            stop_thread = False
            private_key_path = private_key_entry.get()
            pin = pin_entry.get()

            if not document_path or not private_key_path or not pin:
                messagebox.showerror("Błąd", "Wszystkie pola muszą być wypełnione.")
                return

            try:
                private_key = read_key.read_and_decrypt_key(private_key_path, pin)

                signature, document_hash = sign_document(document_path, private_key)
                message = generate_xades_signature(document_path, signature, document_hash)
                messagebox.showinfo("Sukces", message)
                sign_document_window.destroy()
            except Exception as e:
                messagebox.showerror("Błąd", str(e))
                sign_document_window.destroy()

        def choose_document_path():
            path = filedialog.askopenfilename(title="Wybierz dokument do podpisania")
            if path:
                document_entry.delete(0, tk.END)
                document_entry.insert(0, path)

        def choose_private_key_path():
            path = filedialog.askopenfilename(title="Wybierz zaszyfrowany klucz prywatny")
            if path:
                private_key_entry.delete(0, tk.END)
                private_key_entry.insert(0, path)

        def update_private_key_path(private_key_path):
            global stop_thread
            stop_thread = True
            private_key_entry.delete(0, tk.END)
            private_key_entry.insert(0, private_key_path)
            messagebox.showinfo("Klucz prywatny znaleziony", f"Klucz prywatny znaleziony: {private_key_path}")

        sign_document_window = tk.Toplevel(root)
        sign_document_window.title("Podpisywanie dokumentu")

        tk.Label(sign_document_window, text="Ścieżka do dokumentu:").grid(row=0, column=0, sticky='e')
        document_entry = tk.Entry(sign_document_window, width=50)
        document_entry.grid(row=0, column=1)
        tk.Button(sign_document_window, text="Wybierz", command=choose_document_path).grid(row=0, column=2)

        tk.Label(sign_document_window, text="Ścieżka do klucza prywatnego:").grid(row=1, column=0, sticky='e')
        private_key_entry = tk.Entry(sign_document_window, width=50)
        private_key_entry.grid(row=1, column=1)
        tk.Button(sign_document_window, text="Wybierz", command=choose_private_key_path).grid(row=1, column=2)

        tk.Label(sign_document_window, text="Wprowadź PIN:").grid(row=2, column=0, sticky='e')
        pin_entry = tk.Entry(sign_document_window, show='*', width=30)
        pin_entry.grid(row=2, column=1)

        tk.Button(sign_document_window, text="Podpisz dokument", command=sign_document_action).grid(row=3, columnspan=3,
                                                                                                    pady=10)
        global stop_thread
        stop_thread = False
        threading.Thread(target=usb_monitor, args=(update_private_key_path,), daemon=True).start()

    def verify_signature_gui():
        def verify_signature_action():
            document_path = document_entry.get()
            xml_path = xml_entry.get()
            public_key_path = public_key_entry.get()

            if not document_path or not xml_path or not public_key_path:
                messagebox.showerror("Błąd", "Wszystkie pola muszą być wypełnione.")
                return

            try:
                public_key = read_key.read_public(public_key_path)
                result = verify.verify_signature(document_path, xml_path, public_key)
                if result:
                    messagebox.showinfo("Sukces", "Podpis jest prawidłowy.")
                else:
                    messagebox.showerror("Błąd", "Podpis jest nieprawidłowy.")
            except Exception as e:
                messagebox.showerror("Błąd", str(e))

        def choose_document_path():
            path = filedialog.askopenfilename(title="Wybierz dokument do weryfikacji")
            if path:
                document_entry.delete(0, tk.END)
                document_entry.insert(0, path)

        def choose_xml_path():
            path = filedialog.askopenfilename(title="Wybierz plik XML z podpisem")
            if path:
                xml_entry.delete(0, tk.END)
                xml_entry.insert(0, path)

        def choose_public_key_path():
            path = filedialog.askopenfilename(title="Wybierz klucz publiczny")
            if path:
                public_key_entry.delete(0, tk.END)
                public_key_entry.insert(0, path)

        verify_signature_window = tk.Toplevel(root)
        verify_signature_window.title("Weryfikacja podpisu")

        tk.Label(verify_signature_window, text="Ścieżka do dokumentu:").grid(row=0, column=0, sticky='e')
        document_entry = tk.Entry(verify_signature_window, width=50)
        document_entry.grid(row=0, column=1)
        tk.Button(verify_signature_window, text="Wybierz", command=choose_document_path).grid(row=0, column=2)

        tk.Label(verify_signature_window, text="Ścieżka do pliku XML z podpisem:").grid(row=1, column=0, sticky='e')
        xml_entry = tk.Entry(verify_signature_window, width=50)
        xml_entry.grid(row=1, column=1)
        tk.Button(verify_signature_window, text="Wybierz", command=choose_xml_path).grid(row=1, column=2)

        tk.Label(verify_signature_window, text="Ścieżka do klucza publicznego:").grid(row=2, column=0, sticky='e')
        public_key_entry = tk.Entry(verify_signature_window, width=50)
        public_key_entry.grid(row=2, column=1)
        tk.Button(verify_signature_window, text="Wybierz", command=choose_public_key_path).grid(row=2, column=2)

        tk.Button(verify_signature_window, text="Zweryfikuj podpis", command=verify_signature_action).grid(row=3,
                                                                                                           columnspan=3,
                                                                                                           pady=10)

    def encrypt_gui():
        file_path = filedialog.askopenfilename(title="Wybierz lokalizacje pliku")
        rozszerzenie = file_path.split(".")[-1]
        text = ""
        if rozszerzenie == "txt":
            f = open(file_path, "r")
            text = f.read()
            f.close()
        elif rozszerzenie == "odt":
            text = read_odt_file(file_path)
        key_path = filedialog.askopenfilename(title="Wybierz lokalizacje do klucza publicznego")
        encrypted_text = en(text, key_path)
        new_path = file_path + ".enc"
        with open(new_path, "wb") as f:
            f.write(encrypted_text)
        f.close()

    def decrypt_gui():
        file_path = filedialog.askopenfilename(title="Wybierz lokalizacje zaszyfrowanego pliku")
        f = open(file_path, "rb")
        text = f.read()
        key_path = filedialog.askopenfilename(title="Wybierz lokalizacje do klucza prywatnego")
        pin = input("Enter your PIN: ")
        key = read_key.read_and_decrypt_key(key_path, pin)
        dec_text = dec(key, text)
        f.close()
        rozszerzenie = file_path.split(".")[-2]
        if rozszerzenie == "txt":
            new_path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="odczytany.txt",
                                                    title="Wybierz lokalizacje do zapisania odszyfrowanego pliku")
            with open(new_path, "w") as f:
                f.write(dec_text.decode("utf-8"))
            f.close()
        elif rozszerzenie == "odt":
            new_path = filedialog.asksaveasfilename(defaultextension=".odt", initialfile="odczytany.odt",
                                                    title="Wybierz lokalizacje do zapisania odszyfrowanego pliku")
            write_to_odt_file(new_path, dec_text.decode("utf-8"))
        print(dec_text)

    root.title("Aplikacja do podpisywania i weryfikacji dokumentów")
    tk.Button(root, text="Generowanie kluczy RSA", command=generate_keys_gui).pack(pady=10)
    tk.Button(root, text="Podpisywanie dokumentu", command=sign_document_gui).pack(pady=10)
    tk.Button(root, text="Weryfikacja podpisu", command=verify_signature_gui).pack(pady=10)
    tk.Button(root, text="Zaszyfruj plik", command=encrypt_gui).pack(pady=10)
    tk.Button(root, text="Odszyfruj plik", command=decrypt_gui).pack(pady=10)

    root.mainloop()


if __name__ == '__main__':
    create_gui()
    '''app()

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

    verify.verify_signature(document_path, xml_path)'''
