# parsers/gzip_dir_parser.py
# Извлекаемые признаки:
#  - gzip_header_ok (bool)     — сигнатура 1F 8B и метод CM=8 (deflate)
#  - gzip_mtime_present (bool) — поле MTIME существует и ненулевое
#  - gzip_name_present (bool)  — установлен флаг FNAME и имя непустое (NUL-terminated)
#
# Запуск:
#   python parsers/gzip_dir_parser.py <DIR_WITH_FILES>
#
# Примечания:
#   - Предполагается, что в директории лежат gzip/однофайловые контейнеры; расширения не проверяем.
#   - Минимум обработчиков ошибок — проблемные файлы пропускаются молча.
#   - Парсится только первый член (если gzip содержит конкатенацию нескольких членов).

import os
import sys
import struct

# GZIP header constants (RFC 1952)
ID1 = 0x1F
ID2 = 0x8B
CM_DEFLATE = 8

# FLG bits
FTEXT   = 0x01
FHCRC   = 0x02
FEXTRA  = 0x04
FNAME   = 0x08
FCOMMENT= 0x10
# (0xE0 зарезервировано)

BASE_HDR_LEN = 10  # ID1 ID2 CM FLG MTIME(4) XFL OS

def parse_gzip_header(path):
    try:
        with open(path, "rb") as f:
            data = f.read(64 * 1024)  # для заголовка более чем достаточно
    except Exception:
        return None

    # Базовая проверка длины и сигнатуры
    if len(data) < BASE_HDR_LEN:
        return {
            "gzip_header_ok": False,
            "gzip_mtime_present": False,
            "gzip_name_present": False,
            "parser_ok": False,
            "structure_consistent": False,
        }

    id1, id2, cm, flg = data[0], data[1], data[2], data[3]
    gzip_header_ok = (id1 == ID1 and id2 == ID2 and cm == CM_DEFLATE)

    # MTIME — всегда присутствует в базовом заголовке (байты 4..7, LE), но может быть 0
    try:
        mtime = struct.unpack_from("<I", data, 4)[0]
    except Exception:
        mtime = 0
    gzip_mtime_present = bool(mtime != 0)

    # Сдвиг после базового заголовка
    pos = BASE_HDR_LEN
    n = len(data)

    # Пропускаем FEXTRA, если есть
    if flg & FEXTRA:
        if pos + 2 > n:
            return {
                "gzip_header_ok": gzip_header_ok,
                "gzip_mtime_present": gzip_mtime_present,
                "gzip_name_present": False,
                "parser_ok": bool(gzip_header_ok),
                "structure_consistent": bool(gzip_header_ok),
            }
        xlen = struct.unpack_from("<H", data, pos)[0]
        pos += 2 + xlen
        if pos > n:
            return {
                "gzip_header_ok": gzip_header_ok,
                "gzip_mtime_present": gzip_mtime_present,
                "gzip_name_present": False,
                "parser_ok": bool(gzip_header_ok),
                "structure_consistent": bool(gzip_header_ok),
            }

    # Читаем FNAME (NUL-terminated), если есть
    gzip_name_present = False
    if flg & FNAME:
        start = pos
        # ищем нулевой байт
        while pos < n and data[pos] != 0:
            pos += 1
        if pos < n and pos > start:
            gzip_name_present = True
        # пропускаем завершающий NUL (если он есть)
        if pos < n:
            pos += 1

    # Пропускаем FCOMMENT (если есть)
    if flg & FCOMMENT:
        while pos < n and data[pos] != 0:
            pos += 1
        if pos < n:
            pos += 1

    # Пропускаем FHCRC (если есть)
    if flg & FHCRC:
        pos += 2  # CRC16 по заголовку; проверять не требуется

    return {
        "gzip_header_ok": bool(gzip_header_ok),
        "gzip_mtime_present": bool(gzip_mtime_present),
        "gzip_name_present": bool(gzip_name_present),
        "parser_ok": bool(gzip_header_ok),
        "structure_consistent": bool(gzip_header_ok),
    }

def main(dir_path):
    cols = ["file", "gzip_header_ok", "gzip_mtime_present", "gzip_name_present", "parser_ok", "structure_consistent"]
    print("\t".join(cols))

    for fname in sorted(os.listdir(dir_path)):
        path = os.path.join(dir_path, fname)
        if not os.path.isfile(path):
            continue
        try:
            feats = parse_gzip_header(path)
            if feats is None:
                continue
            row = {"file": fname, **feats}
            print("\t".join(str(row[c]) for c in cols))
        except Exception:
            # минимализм: проблемный файл пропускаем молча
            pass

if __name__ == "__main__":
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    main(d)
