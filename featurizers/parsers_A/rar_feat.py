# parsers_A/rar_feat.py

import struct

# Сигнатуры RAR
RAR4_SIG = b'Rar!\x1A\x07\x00'   # 7 байт
RAR5_SIG = b'Rar!\x1A\x07\x01\x00'  # 8 байт

# Типы блоков RAR v4
RAR4_BLOCK_MARK      = 0x72  # MARK_HEAD (не всегда присутствует в файле)
RAR4_BLOCK_MAIN      = 0x73  # MAIN_HEAD
RAR4_BLOCK_FILE      = 0x74  # FILE_HEAD
RAR4_BLOCK_OLD_SERV  = 0x75
RAR4_BLOCK_OLD_COMM  = 0x76
RAR4_BLOCK_OLD_AV    = 0x77
RAR4_BLOCK_SUBBLOCK  = 0x7a
RAR4_BLOCK_ENDARC    = 0x7b

# Флаги RAR v4 (важные)
RAR4_FLAG_ADD_SIZE = 0x8000  # признак наличия ADD_SIZE (доп. 4 байта) в заголовке блока

# Стандартные значения возврата парсера
DEF_RETURN = {
    "rar_header_ok": False,
    "rar_main_header_flags_ok": False,
    "rar_file_records_count": 0,
    "parser_ok": False,
    "structure_consistent": False
}


def read_at(fp, offset, size):
    fp.seek(0, 2)
    end = fp.tell()
    if offset < 0 or offset >= end:
        return b""
    fp.seek(offset)
    return fp.read(min(size, end - offset))

def get_file_size(fp):
    cur = fp.tell()
    fp.seek(0, 2)
    end = fp.tell()
    fp.seek(cur, 0)
    return end

def detect_rar_version(path):
    with open(path, 'rb') as f:
        head = f.read(10)
    if head.startswith(RAR5_SIG):
        return 'v5'
    if head.startswith(RAR4_SIG):
        return 'v4'
    # иногда встречается «голый» v4 без явного MARK_HEAD в начале — для нашего кейса считаем неизвестным
    return None

def parse_rar4(path):
    with open(path, 'rb') as f:
        data = f.read(7)
        if data != RAR4_SIG:
            # Некоторые файлы могут не иметь стартового MARK_HEAD; в таком случае попытаемся
            # начать сразу с первого блока (редко, но встречается). Вернёмся в начало.
            f.seek(0)
        size = get_file_size(f)

        pos = f.tell()
        file_count = 0
        header_ok = False
        main_flags_ok = False
        seen_main = False

        # Итерация по блокам: каждый заголовок минимум 7 байт (CRC(2)+Type(1)+Flags(2)+Size(2))
        while True:
            if pos + 7 > size:
                break
            f.seek(pos)
            hdr = f.read(7)
            if len(hdr) < 7:
                break

            head_crc, head_type, head_flags, head_size = struct.unpack('<HBHH', hdr)
            # sanity check:
            if head_size < 7:
                # странный блок — завершаемся
                break

            add_size = 0
            if (head_flags & RAR4_FLAG_ADD_SIZE) != 0:
                # у некоторых блоков после базовых 7 байт идёт дополнительное 4-байтовое поле ADD_SIZE
                # располагается сразу после фиксированной части заголовка (т.е. внутри head_size)
                if pos + 7 + 4 > size:
                    break
                add_size = struct.unpack('<I', read_at(f, pos + 7, 4))[0]

            block_total = head_size + add_size
            if pos + block_total > size:
                break  # указывает на поломанную структуру

            if head_type == RAR4_BLOCK_MAIN:
                seen_main = True
                # простая проверка флагов MAIN: сам факт корректного перехода и head_size >= 7 считаем достаточным
                main_flags_ok = True

            if head_type == RAR4_BLOCK_FILE:
                file_count += 1

            header_ok = True
            # Переходим к следующему блоку
            pos += block_total

            if head_type == RAR4_BLOCK_ENDARC:
                break
        parser_ok = header_ok and main_flags_ok
        structure_consistent = parser_ok and file_count > 0
        # Итог: «валидным» считаем если хотя бы один блок прочитали и видели MAIN_HEAD
        return {
            "rar_header_ok": bool(header_ok and seen_main),
            "rar_main_header_flags_ok": bool(main_flags_ok),
            "rar_file_records_count": int(file_count),
            "rar_version_5": False,
            "parser_ok": bool(parser_ok),
            "structure_consistent": bool(structure_consistent)
        }

def parse_rar5(path):
    with open(path, "rb") as f:
        f.seek(8)  # сигнатура Rar!
        data = f.read(64)
        # в RAR5 после сигнатуры идёт блок с длиной и типом
        # если блок имеет тип в допустимом диапазоне и длину < 64К — считаем, что блоки присутствуют
        if len(data) >= 7:
            block_size = int.from_bytes(data[0:4], "little")
            block_type = data[4]
            if 1 <= block_type <= 0x7f and 0 < block_size < 65536:
                blocks_present = True
            else:
                blocks_present = False
        else:
            blocks_present = False

    return {
        "rar_header_ok": True,
        "rar_main_header_flags_ok": True,
        "rar_file_records_count": 0,
        "rar_version_5": True,
        "parser_ok": True,
        "structure_consistent": bool(blocks_present)
    }

def parse_rar(path: str) -> dict:
    try:
        ver = detect_rar_version(path)
        if ver == 'v4':
            return(parse_rar4(path))
        elif ver == 'v5':
            return(parse_rar5(path))
        else:
            return DEF_RETURN.copy()
    except Exception:
        return DEF_RETURN.copy()
