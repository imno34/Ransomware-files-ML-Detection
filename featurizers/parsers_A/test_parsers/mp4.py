# parsers/mp4_dir_parser.py
# Извлекаемые признаки:
#  - mp4_ftyp_present (bool)
#  - mp4_moov_present (bool)
#  - mp4_mdat_present (bool)
#  - mp4_brand (enum/string, укрупнённо, берём major_brand из ftyp)
#  - mp4_box_tree_ok (bool) — базовая согласованность размеров боксов (top-level + внутри moov)
#
# Запуск:
#   python parsers/mp4_dir_parser.py <DIR_WITH_FILES>
#
# Примечания:
#   - Предполагается, что в директории лежат MP4/ISO BMFF файлы; расширение не проверяем.
#   - Минимум обработчиков ошибок — проблемные файлы пропускаются молча.
#   - «OK» по дереву означает, что удалось корректно пройти боксы без выхода за границы файла/родителя.

import os
import sys
import struct

def fsize(fp):
    cur = fp.tell()
    fp.seek(0, 2)
    end = fp.tell()
    fp.seek(cur, 0)
    return end

def read_at(fp, off, n):
    fp.seek(0, 2)
    end = fp.tell()
    if off < 0 or off >= end:
        return b""
    fp.seek(off)
    return fp.read(min(n, end - off))

def read_u32(b, off=0):
    if off + 4 > len(b): return None
    return struct.unpack_from(">I", b, off)[0]

def read_u64(b, off=0):
    if off + 8 > len(b): return None
    return struct.unpack_from(">Q", b, off)[0]

def read_type(b, off=0):
    if off + 4 > len(b): return None
    t = b[off:off+4]
    # безопасное представление
    try:
        return t.decode("ascii", errors="ignore")
    except Exception:
        return ""

def iter_boxes(fp, start, end):
    """
    Итератор по боксам в диапазоне [start, end).
    Возвращает кортежи: (typ:str, box_start:int, box_size:int, header_size:int)
    где header_size = 8 (size+type) или 16 (size=1 + largesize).
    Правила ISO BMFF:
      - size == 0  → бокс тянется до конца контейнера (end)
      - size == 1  → largesize (u64) после type
    """
    pos = start
    limit = end
    max_steps = 1_000_000  # предохранитель
    steps = 0
    while pos + 8 <= limit and steps < max_steps:
        steps += 1
        head = read_at(fp, pos, 16)  # хватит и для largesize
        if len(head) < 8:
            break
        size32 = read_u32(head, 0)
        btype  = read_type(head, 4)
        if size32 is None:
            break

        hdr_size = 8
        if size32 == 1:
            # largesize
            if len(head) < 16:
                break
            largesize = read_u64(head, 8)
            if largesize is None or largesize < 16:
                break
            box_size = int(largesize)
            hdr_size = 16
        elif size32 == 0:
            # до конца контейнера
            box_size = limit - pos
            hdr_size = 8
        else:
            box_size = int(size32)

        # sanity
        if box_size < hdr_size:
            break
        if pos + box_size > limit:
            break

        yield (btype, pos, box_size, hdr_size)

        pos += box_size

def validate_box_range(fp, start, end):
    """
    Базовая проверка: можно ли пройти все боксы в диапазоне, не выходя за границы,
    и суммарно покрыть диапазон (с допуском «дыр» после последнего бокса).
    Возвращает bool.
    """
    pos = start
    limit = end
    ok = True
    max_steps = 1_000_000
    steps = 0
    for (typ, bstart, bsize, hdr) in iter_boxes(fp, start, end):
        steps += 1
        # продвигаемся строго вперёд
        if bstart != pos:
            # разрешим пропуски нулевой длины (не должно быть), иначе это несовпадение
            ok = False
            break
        pos += bsize
        if steps > max_steps:
            ok = False
            break
    # допускаем, что за последним боксом могут быть паддинги; критично, чтобы не было out-of-bounds
    return ok

def parse_mp4_one(path):
    with open(path, "rb") as fp:
        size = fsize(fp)
        if size < 8:
            return {
                "mp4_ftyp_present": False,
                "mp4_moov_present": False,
                "mp4_mdat_present": False,
                "mp4_brand": "",
                "mp4_box_tree_ok": False,
            }

        ftyp_present = False
        moov_present = False
        mdat_present = False
        brand = ""
        toplevel_ok = validate_box_range(fp, 0, size)

        # обходим топ-левел боксы для признаков
        for (typ, off, bsize, hdr) in iter_boxes(fp, 0, size):
            if typ == "ftyp":
                ftyp_present = True
                # major_brand = первые 4 байта данных ftyp
                # структура ftyp: size(4) type(4) major_brand(4) minor_version(4) compatible_brands(...)
                head = read_at(fp, off + hdr, 8)
                if len(head) >= 4:
                    try:
                        brand = head[:4].decode("ascii", errors="ignore")
                    except Exception:
                        brand = ""
            elif typ == "moov":
                moov_present = True
                # базовая проверка вложенных боксов в moov
                moov_ok = validate_box_range(fp, off + hdr, off + bsize)
                toplevel_ok = toplevel_ok and moov_ok
            elif typ == "mdat":
                mdat_present = True
            # прочие боксы нас не интересуют (free, skip, wide, mfra и т.п.)

        return {
            "mp4_ftyp_present": bool(ftyp_present),
            "mp4_moov_present": bool(moov_present),
            "mp4_mdat_present": bool(mdat_present),
            "mp4_brand": brand,
            "mp4_box_tree_ok": bool(toplevel_ok),
        }

def main(dir_path):
    cols = [
        "file",
        "mp4_ftyp_present",
        "mp4_moov_present",
        "mp4_mdat_present",
        "mp4_brand",
        "mp4_box_tree_ok",
    ]
    print("\t".join(cols))

    for fname in sorted(os.listdir(dir_path)):
        p = os.path.join(dir_path, fname)
        if not os.path.isfile(p):
            continue
        try:
            feats = parse_mp4_one(p)
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
