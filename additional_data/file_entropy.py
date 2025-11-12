# -*- coding: utf-8 -*-
from pathlib import Path
from collections import Counter
import math
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16  # AES block size


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def aes256_cbc_encrypt(data: bytes) -> bytes:
    key = get_random_bytes(32)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pkcs7_pad(data))


def byte_hist(data: bytes):
    c = Counter(data)
    return [c.get(i, 0) for i in range(256)]


def shannon_entropy(data: bytes) -> float:
    n = len(data)
    if n == 0:
        return 0.0
    counts = byte_hist(data)
    H = 0.0
    for cnt in counts:
        if cnt:
            p = cnt / n
            H -= p * math.log2(p)
    return H


print("=== Средняя энтропия файлов до и после шифрования AES-CBC ===")
dir_path = input("Укажи путь до директории с файлами одного формата: ").strip()
dir_path = Path(dir_path).expanduser()

entropies_plain = []
entropies_cipher = []

for f in dir_path.iterdir():
    if f.is_file():
        data = f.read_bytes()
        cipher = aes256_cbc_encrypt(data)

        H_plain = shannon_entropy(data)
        H_cipher = shannon_entropy(cipher)

        entropies_plain.append(H_plain)
        entropies_cipher.append(H_cipher)
        print(f"{f.name:40s} | энтропия: {H_plain:.4f} → {H_cipher:.4f}")

if entropies_plain:
    avg_plain = sum(entropies_plain) / len(entropies_plain)
    avg_cipher = sum(entropies_cipher) / len(entropies_cipher)
    print("\n--- Итог ---")
    print(f"Средняя энтропия исходных файлов:    {avg_plain:.4f} бит/байт")
    print(f"Средняя энтропия зашифрованных:      {avg_cipher:.4f} бит/байт")
else:
    print("В директории не найдено файлов.")
