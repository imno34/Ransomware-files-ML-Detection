# parsers/rar_dir_parser.py
# Извлекаемые признаки:
#  - rar_header_ok (bool)
#  - rar_version (enum: v4/v5)
#  - rar_main_header_flags_ok (bool)
#  - rar_file_records_count (int)
#
# Предполагается, что в директории лежат RAR-файлы (магия не проверяется здесь).
# Минимум обработчиков ошибок: проблемные файлы пропускаются молча.

import os
import sys
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
    """
    Упрощённый проход по RAR v4:
      - rar_header_ok: True, если нашли MAIN_HEAD и корректно шагнули по блокам без выхода за файл
      - rar_main_header_flags_ok: True, если MAIN_HEAD выглядел правдоподобно (размер >= 7, не вышли за файл)
      - rar_file_records_count: число FILE_HEAD блоков
    """
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
            # Базовая правдоподобность:
            if head_size < 7:
                # странный блок — заканчиваем
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

        # Итог: «валидным» считаем если хотя бы один блок прочитали и видели MAIN_HEAD
        return {
            "rar_header_ok": bool(header_ok and seen_main),
            "rar_main_header_flags_ok": bool(main_flags_ok),
            "rar_file_records_count": int(file_count),
        }

def parse_rar5(path):
    """
    Лайтовая поддержка RAR v5:
      - Определяем версию по сигнатуре.
      - rar_header_ok = True (сигнатура найдена).
      - rar_main_header_flags_ok = True (мы не делаем глубокую проверку v5-блоков в минималистичном варианте).
      - rar_file_records_count = 0 (без детального прохода блоков).
    Примечание: детальный парсинг RAR5 заметно сложнее (varint-поля и пр.) и не нужен
    для нашей первой итерации структуры A-признаков.
    """
    return {
        "rar_header_ok": True,
        "rar_main_header_flags_ok": True,
        "rar_file_records_count": 0,
    }

def parse_rar_features_one(path):
    ver = detect_rar_version(path)
    if ver == 'v4':
        feats = parse_rar4(path)
        feats["rar_version"] = "v4"
        return feats
    elif ver == 'v5':
        feats = parse_rar5(path)
        feats["rar_version"] = "v5"
        return feats
    else:
        # Неизвестная/повреждённая сигнатура — пропустим файл
        return None

def main(dir_path):
    cols = [
        "file",
        "rar_header_ok",
        "rar_version",
        "rar_main_header_flags_ok",
        "rar_file_records_count",
    ]
    print("\t".join(cols))

    for fname in sorted(os.listdir(dir_path)):
        path = os.path.join(dir_path, fname)
        if not os.path.isfile(path):
            continue
        try:
            feats = parse_rar_features_one(path)
            if feats is None:
                continue
            row = {"file": fname, **feats}
            print("\t".join(str(row[c]) for c in cols))
        except Exception:
            # минимализм: проблемный файл пропускаем
            pass

if __name__ == "__main__":
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    main(d)
