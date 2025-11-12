# parsers_A/zip_feat.py

import os
import struct

EOCD_SIG = 0x06054B50  # 'PK\x05\x06'
CDH_SIG  = 0x02014B50  # 'PK\x01\x02'
LFH_SIG  = 0x04034B50  # 'PK\x03\x04'

MAX_EOCD_SEARCH = 0x10000 + 22  # стандартно ищем EOCD в последних ~64К + минимальный размер EOCD
READ_CHUNK = 1 << 20            # 1 MB блоками при необходимости (тут почти не нужно)

# Стандартные значения возврата парсера
DEF_RETURN = {
    "zip_central_dir_ok": False,
    "zip_cd_offset_ok": False,
    "zip_entry_count": 0,
    "zip_has_content_types": False,
    "zip_comment_len": 0,
    "zip_names_utf8_fraction": 0.0,
    "zip_crc_present_fraction": 0.0,
    "parser_ok": False,
    "structure_consistent": False
}

def read_bytes(path, offset, size):
    with open(path, 'rb') as f:
        f.seek(0, 2)
        end = f.tell()
        if offset < 0 or offset >= end:
            return b''
        f.seek(offset)
        return f.read(min(size, end - offset))

def file_size(path):
    return os.path.getsize(path)

def find_eocd(path, fsize):
    """ Поиск EOCD ('PK\\x05\\x06') в хвосте файла. Возвращает (pos, data) или (None, None). """
    search = min(MAX_EOCD_SEARCH, fsize)
    tail = read_bytes(path, fsize - search, search)
    # ищем сигнатуру с конца
    idx = tail.rfind(b'PK\x05\x06')
    if idx == -1:
        return None, None
    pos = fsize - search + idx
    # Минимальная длина EOCD = 22 байта
    eocd = read_bytes(path, pos, 22)
    if len(eocd) < 22:
        return None, None
    return pos, eocd

def parse_eocd(eocd):
    """ Разбор минимального EOCD (без комментария). Возвращает словарь полей. """
    # Структура EOCD:
    #  0  4  signature (0x06054b50)
    #  4  2  disk_no
    #  6  2  cd_start_disk
    #  8  2  entries_on_disk
    # 10  2  entries_total
    # 12  4  cd_size
    # 16  4  cd_offset
    # 20  2  comment_len
    sig = struct.unpack_from('<I', eocd, 0)[0]
    if sig != EOCD_SIG:
        return None
    disk_no, cd_start_disk, entries_on_disk, entries_total, cd_size, cd_offset, comment_len = \
        struct.unpack_from('<HHHHIIH', eocd, 4)
    return {
        'entries_total': entries_total,
        'cd_size': cd_size,
        'cd_offset': cd_offset,
        'comment_len': comment_len
    }

def iter_central_directory(path, cd_offset, cd_size, expected_entries):
    """
    Итератор по записям центрального каталога.
    Возвращает кортежи (ok, name, gpbf, crc).
      ok: bool — сигнатура и базовая структура валидны
      name: bytes — имя файла из центрального каталога
      gpbf: int — general purpose bit flag (для UTF-8 бита)
      crc: int  — CRC из каталога
    Останавливается по размеру каталога или по числу записей.
    """
    data = read_bytes(path, cd_offset, cd_size)
    pos = 0
    count = 0
    while pos + 46 <= len(data):  # 46 — размер фиксированной части CDH
        sig = struct.unpack_from('<I', data, pos)[0]
        if sig != CDH_SIG:
            break
        # Парсим фиксированную часть заголовка
        # смещение в CDH:
        #  0 sig (4)
        #  4 ver_made (2)
        #  6 ver_needed (2)
        #  8 gpbf (2)
        # 10 comp_method (2)
        # 12 mod_time (2)
        # 14 mod_date (2)
        # 16 crc32 (4)
        # 20 comp_size (4)
        # 24 uncomp_size (4)
        # 28 fname_len (2)
        # 30 extra_len (2)
        # 32 comment_len (2)
        # 34 disk_num_start (2)
        # 36 int_attr (2)
        # 38 ext_attr (4)
        # 42 rel_lfh_off (4)
        fields = struct.unpack_from('<HHHHHHIIIHHHHHII', data, pos + 4)
        gpbf        = fields[2]
        crc32       = fields[6]
        fname_len   = fields[9]
        extra_len   = fields[10]
        comment_len = fields[11]

        name_start = pos + 46
        name_end   = name_start + fname_len
        if name_end > len(data):
            break
        name = data[name_start:name_end]

        total_len = 46 + fname_len + extra_len + comment_len
        pos += total_len
        count += 1
        yield True, name, gpbf, crc32

        if expected_entries and count >= expected_entries:
            # по EOCD ожидается столько записей — можно остановиться
            break

def parse_zip(path:str) -> dict:
    try:
        fsize = file_size(path)
        # Проверим EOCD
        eocd_pos, eocd = find_eocd(path, fsize)
        if eocd_pos is None:
            return None  # не ZIP или сильно повреждён
        e = parse_eocd(eocd)
        if e is None:
            return None

        entries_total = e['entries_total']
        cd_size       = e['cd_size']
        cd_offset     = e['cd_offset']
        comment_len   = e['comment_len']

        # Проверка правдоподобности смещения CD
        # Условие: cd_offset + cd_size <= fsize, и в начале CD — сигнатура CDH
        zip_cd_offset_ok = (cd_offset + cd_size <= fsize) and (
            struct.unpack_from('<I', read_bytes(path, cd_offset, 4), 0)[0] == CDH_SIG
        )

        # Итерация по центральному каталогу
        entry_count = 0
        utf8_count = 0
        crc_present_count = 0
        has_content_types = False

        for ok, name, gpbf, crc in iter_central_directory(path, cd_offset, cd_size, entries_total):
            if not ok:
                break
            entry_count += 1
            # bit 11 (0x0800) — имена в UTF-8
            if (gpbf & 0x0800) != 0:
                utf8_count += 1
            if crc != 0:
                crc_present_count += 1
            if name == b'[Content_Types].xml':
                has_content_types = True

        # центральный каталог «ок», если смогли прочитать все заявленные записи
        zip_central_dir_ok = (entries_total == 0 and entry_count == 0) or (entry_count == entries_total)

        # Фракции
        utf8_fraction = (utf8_count / entry_count) if entry_count > 0 else 0.0
        crc_fraction  = (crc_present_count / entry_count) if entry_count > 0 else 0.0

        # Вычислить агрегирующие признаки parser_ok, structure_consistent по посчитанным признакам 
        parser_ok = zip_central_dir_ok and zip_cd_offset_ok and (entry_count >= 1)
        structure_consistent = parser_ok and (crc_fraction >= 0.65)

        return {
            "zip_central_dir_ok": bool(zip_central_dir_ok),
            "zip_cd_offset_ok": bool(zip_cd_offset_ok),
            "zip_entry_count": int(entry_count),
            "zip_has_content_types": bool(has_content_types),
            "zip_comment_len": int(comment_len),
            "zip_names_utf8_fraction": float(round(utf8_fraction, 6)),
            "zip_crc_present_fraction": float(round(crc_fraction, 6)),
            "parser_ok": bool(parser_ok),
            "structure_consistent": bool(structure_consistent)
        }
    except Exception:
        return DEF_RETURN.copy()