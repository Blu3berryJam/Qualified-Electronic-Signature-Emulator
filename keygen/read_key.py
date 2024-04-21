import os
from tkinter import filedialog

IV_SIZE = 16

# klucz jest oczywiście wciąż zaszyfrowany ale można tak odczytać zaszyfrowany klucza i iv z pliku, żeby potem go zdekryptować
def read():
    file_path = filedialog.askopenfilename()
    with open(file_path, "rb") as f:
        file_size = os.path.getsize(file_path)
        epc = f.read(file_size - IV_SIZE)
        f.seek(-IV_SIZE, os.SEEK_END)
        iv = f.read(IV_SIZE)
    print("Wybrano plik:", file_path)
