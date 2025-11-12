# -*- coding: utf-8 -*-
from pathlib import Path
from collections import Counter
import math
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16  # размер блока AES


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def aes256_cbc_encrypt(data: bytes) -> bytes:
    key = get_random_bytes(32)  # 256 бит
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


print("=== Энтропия файла до и после шифрования AES-CBC ===")
path = input("Укажи путь до файла: ").strip()
src_path = Path(path).expanduser()

data = src_path.read_bytes()
ciphertext = aes256_cbc_encrypt(data)

H_plain = shannon_entropy(data)
H_cipher = shannon_entropy(ciphertext)

print(f"\nФайл: {src_path.name}")
print(f"Энтропия исходного файла:    {H_plain:.4f} бит/байт")
print(f"Энтропия шифртекста AES-CBC: {H_cipher:.4f} бит/байт")
