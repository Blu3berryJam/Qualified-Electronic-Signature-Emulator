
import yaml
from cryptography.hazmat.primitives.ciphers import algorithms, modes


def load_config():
    with open("config.yaml", "r") as f:
        config = yaml.safe_load(f)
        encrypt_algorithm = getattr(algorithms, config['ENCRYPTION']['ENCRYPT_ALGORITHM'])
        key_size = int(config['ENCRYPTION']['KEY_SIZE'])
        cipher_mode = getattr(modes, config['ENCRYPTION']['CIPHER_MODE'])
        iv_size = int(config['ENCRYPTION']['IV_SIZE'])

    return encrypt_algorithm, key_size, cipher_mode, iv_size
