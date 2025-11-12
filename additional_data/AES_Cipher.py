import sys
import shutil
from pathlib import Path
from typing import Tuple
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16  # AES block size (bytes)
# You can configure an interval to encrypt: offset (bytes from start) and length.
# Set ENCRYPT_LEN to None or <=0 to encrypt the whole file.
# Example: ENCRYPT_OFFSET=0, ENCRYPT_LEN=4096 encrypts first 4 KiB (backwards compatible)
ENCRYPT_OFFSET = 144
ENCRYPT_LEN = 848

def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def encrypt_bytes_aes_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)

def make_output_paths(src_path: Path, out_dir: Path) -> Tuple[Path, Path]:
    # создаём имя файла с временным суффиксом чтобы не перезаписать случайно
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_name = src_path.name
    keyfile_name = f"{src_path.name}.key.{timestamp}.txt"
    return out_dir / out_name, out_dir / keyfile_name

def main():
    print("=== AES-256 локальное шифрование файла (CBC, PKCS7) ===")
    src = input("Путь до файла для шифрования: ").strip()
    out_dir = input("Путь до папки вывода (будет создана, если нет): ").strip()

    if not src:
        print("Ошибка: путь до файла не задан.")
        sys.exit(1)

    src_path = Path(src).expanduser()
    if not src_path.is_file():
        print(f"Ошибка: файл не найден: {src_path}")
        sys.exit(1)

    out_dir_path = Path(out_dir).expanduser()
    out_dir_path.mkdir(parents=True, exist_ok=True)

    out_file_path, key_file_path = make_output_paths(src_path, out_dir_path)

    # Генерация ключа и IV
    key = get_random_bytes(32)  # AES-256
    iv = get_random_bytes(16)   # 16 байт для CBC

    # Read file and extract prefix, target region, and suffix according to interval
    total_size = src_path.stat().st_size
    enc_offset = int(ENCRYPT_OFFSET) if ENCRYPT_OFFSET is not None else 0
    enc_len = int(ENCRYPT_LEN) if ENCRYPT_LEN is not None else -1

    with src_path.open("rb") as f:
        # Normalize offset
        if enc_offset < 0:
            enc_offset = 0

        # If enc_len <= 0 treat as encrypt whole file
        if enc_len <= 0:
            prefix = b""
            data_to_encrypt = f.read()
            suffix = b""
        else:
            # If offset beyond file, nothing to encrypt
            if enc_offset >= total_size:
                prefix = f.read()
                data_to_encrypt = b""
                suffix = b""
            else:
                # read prefix
                f.seek(0)
                prefix = f.read(enc_offset)
                # read region to encrypt
                data_to_encrypt = f.read(enc_len)
                # rest of file
                suffix = f.read()

    if not data_to_encrypt:
        # Nothing to encrypt: copy original file and write a note in keyfile
        shutil.copy2(src_path, out_file_path)
        with key_file_path.open("w", encoding="utf-8") as kf:
            kf.write("=== No encryption performed (empty or invalid interval) ===\n")
            kf.write(f"Source file: {str(src_path)}\n")
            kf.write("No key generated.\n")
        print()
        print("No bytes were encrypted (interval empty or offset beyond EOF). File copied.")
        print(f"Output file: {out_file_path}")
        return

    # Pad and encrypt the selected portion
    padded = pkcs7_pad(data_to_encrypt)
    ciphertext = encrypt_bytes_aes_cbc(padded, key, iv)

    # Write prefix (plaintext) + IV + ciphertext + suffix
    with out_file_path.open("wb") as f:
        if prefix:
            f.write(prefix)
        # store IV before ciphertext for this encrypted chunk
        f.write(iv)
        f.write(ciphertext)
        if suffix:
            f.write(suffix)

    # Записываем ключ и IV в текстовый файл (hex-строки)
    with key_file_path.open("w", encoding="utf-8") as kf:
        kf.write("=== Ключ и IV для локального теста ===\n")
        kf.write(f"Исходный файл: {str(src_path)}\n")
        kf.write(f"Файл шифртекста: {str(out_file_path)}\n\n")
        kf.write(f"Key (hex): {key.hex()}\n")
        kf.write(f"IV  (hex): {iv.hex()}\n\n")
        kf.write("Примечание: IV также записан в начале файла шифртекста (первые 16 байт).\n")

    print()
    print("Готово.")
    print(f"Зашифрованный файл: {out_file_path}")
    print(f"Файл с key/iv       : {key_file_path}")
    print("Не забудь проверить резервную копию исходного файла!")

if __name__ == "__main__":
    main()