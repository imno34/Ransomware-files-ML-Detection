# parsers_A/mp4_dir_parser.py

import struct


max_steps = 1_000_000

# Стандартные значения возврата парсера
DEF_RETURN = {
"mp4_ftyp_present": False,
"mp4_moov_present": False,
"mp4_mdat_present": False,
"mp4_brand": "",
"mp4_box_tree_ok": False,
"parser_ok": False,
"structure_consistent": False
}


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
    if off + 4 > len(b): 
        return None
    return struct.unpack_from(">I", b, off)[0]

def read_u64(b, off=0):
    if off + 8 > len(b): 
        return None
    return struct.unpack_from(">Q", b, off)[0]

def read_type(b, off=0):
    if off + 4 > len(b): 
        return None
    t = b[off:off+4]
    # безопасное представление
    try:
        return t.decode("ascii", errors="ignore")
    except Exception:
        return ""

def iter_boxes(fp, start, end):
    pos = start
    limit = end
    steps = 0
    while pos + 8 <= limit and steps < max_steps:
        steps += 1
        head = read_at(fp, pos, 16)
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

        if box_size < hdr_size:
            break
        if pos + box_size > limit:
            break

        yield (btype, pos, box_size, hdr_size)

        pos += box_size

def validate_box_range(fp, start, end):
    pos = start
    limit = end
    ok = True
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

def parse_mp4(path: str) -> dict:
    try:
        with open(path, "rb") as fp:
            size = fsize(fp)
            if size < 8:
                return DEF_RETURN.copy()

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

           # Расчет сводных булевых признаков    
            parser_ok = ftyp_present and toplevel_ok and (moov_present or mdat_present)
            structure_consistent = ftyp_present and toplevel_ok and moov_present and mdat_present

            return {
                "mp4_ftyp_present": bool(ftyp_present),
                "mp4_moov_present": bool(moov_present),
                "mp4_mdat_present": bool(mdat_present),
                "mp4_brand": brand,
                "mp4_box_tree_ok": bool(toplevel_ok),
                "parser_ok": bool(parser_ok),
                "structure_consistent": bool(structure_consistent)
            }
    except Exception:
        return DEF_RETURN.copy()