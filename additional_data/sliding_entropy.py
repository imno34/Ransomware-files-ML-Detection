# -*- coding: utf-8 -*-
from pathlib import Path
from collections import Counter
import math
import matplotlib.pyplot as plt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

WIN = 256  # размер окна в байтах (скользящая энтропия)
BLOCK_SIZE = 16  # AES block size

def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def aes256_cbc_encrypt(data: bytes) -> bytes:
    key = get_random_bytes(32)  # 256 бит
    iv  = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pkcs7_pad(data))

def shannon_entropy(b: bytes) -> float:
    n = len(b)
    if n == 0:
        return 0.0
    counts = Counter(b)
    H = 0.0
    for cnt in counts.values():
        p = cnt / n
        H -= p * math.log2(p)
    return H  # бит/байт

def sliding_entropy(data: bytes, win: int = WIN):
    vals = []
    # шаг = размер окна (неперекрывающиеся окна)
    for i in range(0, len(data) - win + 1, win):
        vals.append(shannon_entropy(data[i:i+win]))
    return vals

print("=== Скользящая энтропия (окно 256 байт) до/после AES-CBC ===")
path = input("Укажи путь до файла: ").strip()
p = Path(path).expanduser()

raw = p.read_bytes()
cipher = aes256_cbc_encrypt(raw)

H_raw = sliding_entropy(raw, WIN)
H_cph = sliding_entropy(cipher, WIN)

x = list(range(len(H_raw)))  # индекс окна (0,1,2,...)

plt.figure(figsize=(12, 6))
plt.plot(x, H_raw, label="Исходный файл")
plt.plot(x, H_cph, label="AES-CBC шифртекст")

plt.xlabel("Номер окна (по 256 байт)")
plt.ylabel("Энтропия Шеннона, бит/байт")
plt.title(f"Скользящая энтропия: {p.name} (окно = {WIN} байт, шаг = {WIN})")
plt.ylim(0, 8.1)
plt.grid(True, linewidth=0.5, alpha=0.6)
plt.legend()
plt.tight_layout()
plt.show()
