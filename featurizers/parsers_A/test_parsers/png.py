# parsers/png_dir_parser.py
# Извлекаемые признаки:
#  - png_header_ok (bool)
#  - png_ihdr_ok (bool)
#  - png_chunks_count (int)
#  - png_idat_count (int)
#  - png_end_iend_ok (bool)
#
# Запуск:
#   python parsers/png_dir_parser.py <DIR_WITH_FILES>
#
# Примечания:
#   - Директория предполагается отсортированной под PNG; скрипт сам не фильтрует по расширению.
#   - Минимум обработчиков ошибок — битые/неподходящие файлы пропускаются тихо.

import os
import sys
import struct

PNG_SIG = b"\x89PNG\r\n\x1a\n"
MAX_CHUNKS = 100000  # предохранитель от зацикливания/битых данных
HEADER_LEN = 8

def parse_png_features_one(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception:
        return None

    png_header_ok = data.startswith(PNG_SIG)
    # если даже сигнатуры нет — дальше не углубляемся, но возвращаем валидные дефолты
    if not png_header_ok or len(data) < HEADER_LEN + 12:
        return {
            "png_header_ok": bool(png_header_ok),
            "png_ihdr_ok": False,
            "png_chunks_count": 0,
            "png_idat_count": 0,
            "png_end_iend_ok": False,
        }

    pos = HEADER_LEN
    chunks_count = 0
    idat_count = 0
    ihdr_ok = False
    iend_ok = False
    seen_ihdr = False

    # Первый чанк должен быть IHDR длиной 13
    if pos + 8 <= len(data):
        try:
            ihdr_len = struct.unpack(">I", data[pos:pos+4])[0]
            ihdr_type = data[pos+4:pos+8]
            if ihdr_type == b"IHDR" and ihdr_len == 13 and pos + 12 + ihdr_len <= len(data):
                ihdr_ok = True
                seen_ihdr = True
            # продвинем pos на IHDR (или на то, что там оказалось)
            pos += 8 + ihdr_len + 4  # len(4) + type(4) + data + crc(4)
            chunks_count += 1
        except Exception:
            # не удалось корректно прочитать первый чанк
            return {
                "png_header_ok": True,
                "png_ihdr_ok": False,
                "png_chunks_count": 1,
                "png_idat_count": 0,
                "png_end_iend_ok": False,
            }
    else:
        return {
            "png_header_ok": True,
            "png_ihdr_ok": False,
            "png_chunks_count": 0,
            "png_idat_count": 0,
            "png_end_iend_ok": False,
        }

    # Итерация по остальным чанкам
    steps = 0
    while pos + 8 <= len(data) and steps < MAX_CHUNKS:
        steps += 1
        try:
            length = struct.unpack(">I", data[pos:pos+4])[0]
            ctype = data[pos+4:pos+8]
            next_pos = pos + 8 + length + 4  # len+type+data+crc
            if next_pos > len(data):
                break  # выход за файл → повреждение
            chunks_count += 1
            if ctype == b"IDAT":
                idat_count += 1
            elif ctype == b"IEND":
                iend_ok = True
                pos = next_pos
                break  # IEND — последний чанк
            pos = next_pos
        except Exception:
            break

    # Если после цикла есть ещё байты и мы не встретили IEND — попробуем проверить, не стоял ли он на границе
    # (по хорошему PNG должен завершаться на IEND ровно)
    if not iend_ok and pos == len(data):
        # формально это уже конец файла, но IEND не встретили → считаем iend_ok=False
        pass

    return {
        "png_header_ok": bool(png_header_ok),
        "png_ihdr_ok": bool(ihdr_ok and seen_ihdr),
        "png_chunks_count": int(chunks_count),
        "png_idat_count": int(idat_count),
        "png_end_iend_ok": bool(iend_ok),
    }

def main(dir_path):
    cols = [
        "file",
        "png_header_ok",
        "png_ihdr_ok",
        "png_chunks_count",
        "png_idat_count",
        "png_end_iend_ok",
    ]
    print("\t".join(cols))

    for fname in sorted(os.listdir(dir_path)):
        path = os.path.join(dir_path, fname)
        if not os.path.isfile(path):
            continue
        try:
            feats = parse_png_features_one(path)
            if feats is None:
                continue
            row = {"file": fname, **feats}
            print("\t".join(str(row[c]) for c in cols))
        except Exception:
            # минимализм: проблемные файлы пропускаем
            pass

if __name__ == "__main__":
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    main(d)
