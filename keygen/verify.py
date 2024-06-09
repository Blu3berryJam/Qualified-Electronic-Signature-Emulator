import os
import base64
import hashlib
import lxml.etree as ET
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

from keygen.read_key import read_public


def verify_signature(document_path, xml_path):
    with open(document_path, 'rb') as f:
        document_data = f.read()
    document_hash = hashlib.sha256(document_data).digest()

    public_key = read_public()
    tree = ET.parse(xml_path)
    root = tree.getroot()

    signature_elem = root.find("Signature")
    document_hash_elem = root.find("DocumentHash")

    if signature_elem is None or document_hash_elem is None:
        print("Brak podpisu lub hasha dokumentu w pliku XML.")
        return False

    signature = base64.b64decode(signature_elem.text)
    stored_document_hash = base64.b64decode(document_hash_elem.text)

    try:
        public_key.verify(
            signature,
            stored_document_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except Exception as e:
        print("Weryfikacja podpisu nie powiodła się:", e)
        return False

    if document_hash != stored_document_hash:
        print("Hash dokumentu nie zgadza się z hashem w pliku XML.")
        return False

    print("Podpis jest prawidłowy.")
    return True
