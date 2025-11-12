from pathlib import Path
from collections import Counter
import math

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import matplotlib.pyplot as plt

BLOCK_SIZE = 16  # AES block size

def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def aes256_cbc_encrypt(plaintext: bytes) -> bytes:
    # Случайный ключ и IV: шифруем только в памяти, ничего не сохраняем
    key = get_random_bytes(32)  # 256-bit key
    iv  = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pkcs7_pad(plaintext)
    ciphertext = cipher.encrypt(padded)
    return ciphertext  # IV не добавляем к началу, он не нужен для наших графиков

def byte_histogram(data: bytes):
    # Возвращает список длиной 256: количество каждого байта 0..255
    c = Counter(data)
    return [c.get(i, 0) for i in range(256)]

def normalize_counts(counts):
    total = sum(counts)
    if total == 0:
        return [0.0] * 256
    return [cnt / total for cnt in counts]

def main():
    print("=== Анализ распределения байтов (AES-CBC) ===")
    path = input("Укажи путь до файла: ").strip()

    src_path = Path(path).expanduser()
    if not src_path.is_file():
        print(f"Файл не найден: {src_path}")
        return

    data = src_path.read_bytes()
    ciphertext = aes256_cbc_encrypt(data)


    hist_plain = byte_histogram(data)
    hist_cipher = byte_histogram(ciphertext)

    y_plain = normalize_counts(hist_plain)
    y_cipher = normalize_counts(hist_cipher)

    x = list(range(256))
    plt.figure(figsize=(12, 6))
    plt.plot(x, y_plain, label="Исходный файл")
    plt.plot(x, y_cipher, label="AES-CBC шифртекст")
    plt.xlabel("Значение байта (0–255)")
    plt.ylabel("Относительная частота")
    plt.legend()
    plt.grid(True, linewidth=0.4, alpha=0.5)
    plt.title(f"Распределение байтов: {src_path.name}")
    plt.yticks([i/100 for i in range(0, 11)])  # шаг 0.1 от 0.0 до 1.0
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    main()