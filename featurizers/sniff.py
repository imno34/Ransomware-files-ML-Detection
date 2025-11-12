# sniffer.py
import os
import zipfile
import math
import yaml

# Низкоуровневые функции проверки сигнатур
def _is_pdf(h: bytes)   -> bool: return h.startswith(b"%PDF-")
def _is_png(h: bytes)   -> bool: return h.startswith(b"\x89PNG\r\n\x1a\n")
def _is_jpeg(h: bytes)  -> bool: return h.startswith(b"\xFF\xD8\xFF")
def _is_gzip(h: bytes)  -> bool: return len(h) >= 3 and h[:3] == b"\x1F\x8B\x08"
def _is_ole2(h: bytes)  -> bool: return h.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")
def _is_zip(h: bytes)   -> bool: return h.startswith(b"PK\x03\x04") or h.startswith(b"PK\x05\x06") or h.startswith(b"PK\x07\x08")
def _is_rar(h: bytes)   -> bool: return h.startswith(b"Rar!\x1A\x07\x00") or h.startswith(b"Rar!\x1A\x07\x01\x00")
def _is_mp4(h: bytes)   -> bool: return len(h) >= 12 and h[4:8] == b"ftyp"

# Сигнатуры известных форматов, для которых не написан обработчик 
def _is_gif(h: bytes)   -> bool: return h.startswith(b"GIF87a") or h.startswith(b"GIF89a")
def _is_webp(h: bytes)  -> bool: return len(h) >= 12 and h[0:4] == b"RIFF" and h[8:12] == b"WEBP"
def _is_mp3(h: bytes)   -> bool:
    if h.startswith(b"ID3"): return True
    return len(h) >= 2 and h[0] == 0xFF and (h[1] & 0xE0) == 0xE0
def _is_wav(h: bytes)   -> bool: return len(h) >= 12 and h[0:4] == b"RIFF" and h[8:12] == b"WAVE"
def _is_flac(h: bytes)  -> bool: return h.startswith(b"fLaC")
def _is_bzip2(h: bytes) -> bool: return h.startswith(b"BZh")
def _is_lz4(h: bytes)   -> bool: return h.startswith(b"\x04\x22\x4D\x18")
def _is_zstd(h: bytes)  -> bool: return h.startswith(b"\x28\xB5\x2F\xFD")
def _is_sqlite(h: bytes)-> bool: return h.startswith(b"SQLite format 3\x00")
def _is_pe(h: bytes)    -> bool: return h.startswith(b"MZ")
def _is_elf(h: bytes)   -> bool: return h.startswith(b"\x7FELF")
def _is_7z(h: bytes)    -> bool: return h.startswith(b"7z\xBC\xAF'\x1C") or h.startswith(b"\x37\x7A\xBC\AF\x27\x1C")
def _is_tar(head: bytes, whole: bytes) -> bool:
    # Проверка TAR требует переместиться на смещение 257
    blob = head if len(head) >= 265 else (head + whole)
    return len(blob) >= 265 and blob[257:263] in (b"ustar\x00", b"ustar\x20")

# Проверка ZIP как контейнера OOXML
def _zip_looks_like_ooxml(path: str) -> bool:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
        # Проверка наличия ключевого файла [Content_Types].xml
        # и одной из корневых директорий (word/, xl/, ppt/)
        if "[Content_Types].xml" in names:
            return any(n.startswith(("word/", "xl/", "ppt/")) for n in names)
    except Exception:
        pass
    return False

# Вспомогательная функция для безопасного чтения вложенных ключей из файла конфигурации
def _get(cfg: dict, path: str, default=None):
    # Достаем cfg['a']['b']['c'] по строке 'a.b.c'
    cur = cfg
    for k in path.split('.'):
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

# Основная функция sniff.py по определению формата файла по его сигнатуре
def sniff(path: str, cfg: dict):
    # Загрузка параметров из файла конифгурации
    head_bytes = int(_get(cfg, "global.sniffer.head_bytes", 16384))
    tail_bytes = int(_get(cfg, "global.sniffer.tail_bytes", 16384))
    enabled = set(_get(cfg, "global.sniffer.enabled_families", []) or [])
    fallback_max_attempts = int(_get(cfg, "global.parser.fallback.max_attempts", 0))

    # Чтение заголовка и трейлера файла
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        head = f.read(head_bytes)
        if size >= tail_bytes:
            f.seek(-tail_bytes, os.SEEK_END)
            tail = f.read(tail_bytes)
        else:
            # Если файл маленький, то заголовок и трейлер совпадают
            tail = head

    # Присвоение формата файла, но только по тем, для которых написаны обработчики
    fam = "other"
    if "pdf"   in enabled and _is_pdf(head):  fam = "pdf"
    elif "png" in enabled and _is_png(head):  fam = "png"
    elif "jpeg"in enabled and _is_jpeg(head): fam = "jpeg"
    elif "gzip" in enabled and _is_gzip(head): fam = "gzip"
    elif "ole2" in enabled and _is_ole2(head): fam = "ole2"
    elif "rar"  in enabled and _is_rar(head):  fam = "rar"
    elif "mp4"  in enabled and _is_mp4(head):  fam = "mp4"
    elif ("zip" in enabled or "ooxml" in enabled) and _is_zip(head):
        fam = "ooxml" if ("ooxml" in enabled and _zip_looks_like_ooxml(path)) else ("zip" if "zip" in enabled else "other")

    # Присвоение известных форматов, для которых не написаны обработчики
    magic_ok = False
    magic_family = "unknown"

    # Сначала проверка основных сигнатур, для которых есть обработчики
    if _is_pdf(head):         magic_ok, magic_family = True, "pdf"
    elif _is_png(head):       magic_ok, magic_family = True, "png"
    elif _is_jpeg(head):      magic_ok, magic_family = True, "jpeg"
    elif _is_gzip(head):      magic_ok, magic_family = True, "gzip"
    elif _is_ole2(head):      magic_ok, magic_family = True, "ole2"
    elif _is_rar(head):       magic_ok, magic_family = True, "rar"
    elif _is_mp4(head):       magic_ok, magic_family = True, "mp4"
    elif _is_zip(head):
        magic_ok = True
        magic_family = "ooxml" if _zip_looks_like_ooxml(path) else "zip"
    else:
        # Проверка расширенных сигнатур, для которых нет обработчиков
        if (
            _is_gif(head) or _is_webp(head) or _is_mp3(head) or _is_wav(head) or
            _is_flac(head) or _is_bzip2(head) or _is_lz4(head) or _is_zstd(head) or
            _is_sqlite(head) or _is_tar(head, head if len(head) >= 265 else head+tail) or
            _is_pe(head) or _is_elf(head) or _is_7z(head)
        ):
            magic_ok = True
            # Присвоение служебного признака magic_family
            if   _is_gif(head):   magic_family = "gif"
            elif _is_webp(head):  magic_family = "webp"
            elif _is_mp3(head):   magic_family = "mp3"
            elif _is_wav(head):   magic_family = "wav"
            elif _is_flac(head):  magic_family = "flac"
            elif _is_bzip2(head): magic_family = "bzip2"
            elif _is_lz4(head):   magic_family = "lz4"
            elif _is_zstd(head):  magic_family = "zstd"
            elif _is_sqlite(head):magic_family = "sqlite"
            elif _is_tar(head, head if len(head) >= 265 else head+tail): magic_family = "tar"
            elif _is_pe(head):    magic_family = "pe"
            elif _is_elf(head):   magic_family = "elf"
            elif _is_7z(head):    magic_family = "7z"

    # Вычисление логарифма размера файла (log_size)
    log_size = 0.0
    if size > 0:
        log_size = math.log10(size + 1)
    else: 
        log_size = 0.0

    # Возврат словаря с результатами работы sniff.py
    return {
        "format_family": fam,
        "magic_ok": magic_ok,
        "magic_family": magic_family,
        "size_bytes": size,
        "log_size": log_size,
        "fallback_max_attempts": fallback_max_attempts,
    }

# ------ Код для запуска через CLI (командную строку) ------
if __name__ == "__main__":
    import sys
    import yaml

    # Определение пути к конфигу (по умолчанию или через --cfg)
    cfg_path = "config/features.yaml"
    paths = []
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--cfg" and i + 1 < len(sys.argv):
            cfg_path = sys.argv[i + 1]; i += 2; continue
        paths.append(arg); i += 1

    # Загрузка конфига
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except Exception:
        cfg = {}

    # Запуск 'sniff' для каждого указанного пути
    for p in paths:
        print(p, "=>", sniff(p, cfg))