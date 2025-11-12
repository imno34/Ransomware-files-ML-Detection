# parsers_B/pdf_feat_enc.py
import os
import re
from typing import Optional, Dict

# Размер трейлера
TAIL_READ = 256 * 1024
# Размер заголовка
HEAD_READ = 1 * 1024 * 1024
# Небольшое расширенное окно вокруг найденного /Encrypt
WINDOW_BEFORE = 1024 * 2
WINDOW_AFTER = 1024 * 8

# Регулярные выражения для поска ключевых меток
RE_FILTER_NAME = re.compile(br"/Filter\s*/([A-Za-z0-9]+)")
RE_ENCRYPT_METADATA = re.compile(br"/EncryptMetadata\s+(true|false)", re.IGNORECASE)

# Стандартные значения возврата парсера
DEF_RETURN = {
    "pdf_encrypt_dict_present": False,
    "pdf_encrypt_filter": "",
    "pdf_encrypt_metadata": "",    
}

def read_tail(path: str, max_bytes: int) -> bytes:
    size = os.path.getsize(path)
    n = min(size, max_bytes)
    with open(path, "rb") as f:
        f.seek(size - n)
        return f.read(n)

def read_head(path: str, max_bytes: int) -> bytes:
    with open(path, "rb") as f:
        return f.read(max_bytes)

def decode_ascii(b: Optional[bytes]) -> Optional[str]:
    if not b:
        return None
    try:
        return b.decode("ascii", "ignore")
    except Exception:
        return None

def scan_encrypt_window(buf: bytes) -> Dict[str, Optional[object]]:
    present = False
    enc_filter: Optional[str] = None
    enc_meta: Optional[bool] = None

    pos = buf.find(b"/Encrypt")
    if pos != -1:
        present = True
        start = max(0, pos - WINDOW_BEFORE)
        end = min(len(buf), pos + WINDOW_AFTER)
        win = buf[start:end]

        m = RE_FILTER_NAME.search(win)
        if m:
            enc_filter = decode_ascii(m.group(1))

        m = RE_ENCRYPT_METADATA.search(win)
        if m:
            enc_meta = (m.group(1).lower() == b"true")

        # Если не нашли поблизости, пробуем чуть шире
        if enc_filter is None:
            m2 = RE_FILTER_NAME.search(buf)
            if m2:
                enc_filter = decode_ascii(m2.group(1))
        if enc_meta is None:
            m2 = RE_ENCRYPT_METADATA.search(buf)
            if m2:
                enc_meta = (m2.group(1).lower() == b"true")

    return {
        "pdf_encrypt_dict_present": bool(present),
        "pdf_encrypt_filter": enc_filter,
        "pdf_encrypt_metadata": (bool(enc_meta) if enc_meta is not None else ""),
    }

def parse_pdf_enc(path: str) -> dict:
    """
    Извлекает признаки легитимного шифрования PDF-файла.
    Читает хвост (и при необходимости — голову) без полного парсинга.
    """
    try:
        # 1) Пробуем найти в трейлере
        tail = read_tail(path, TAIL_READ)
        res = scan_encrypt_window(tail)
        if res["pdf_encrypt_dict_present"]:
            return res

        # 2) Если в трейлере не нашли смотрим заголовок
        head = read_head(path, HEAD_READ)
        res2 = scan_encrypt_window(head)
        if res2["pdf_encrypt_dict_present"]:
            return res2

        return {
            "pdf_encrypt_dict_present": False,
            "pdf_encrypt_filter": None,
            "pdf_encrypt_metadata": None,
        }
    except Exception:
        return DEF_RETURN.copy()
