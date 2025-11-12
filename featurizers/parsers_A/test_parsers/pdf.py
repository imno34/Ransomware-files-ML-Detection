# parsers/pdf_dir_parser.py
# Минимальный парсер PDF-признаков по директории.
# Извлекает:
#  - pdf_version (str)
#  - pdf_has_trailer (bool)
#  - pdf_startxref_found (bool)
#  - pdf_xref_ok (bool)
#  - pdf_ids_present (bool)
#  - pdf_root_present (bool)
#  - pdf_trailer_ok (bool)
import os
import sys

DIR = r"C:/Users/30772/OneDrive/Desktop/NIRS_10/NapierOne collections/PDF-tiny"  # <- поменяйте при необходимости

HEAD_READ = 64 * 1024     # сколько читаем с начала
TAIL_READ = 128 * 1024    # сколько читаем с конца
STARTXREF_SCAN = 256 * 1024  # сколько символов с конца сканируем для startxref
NEAR_WINDOW = 4096        # окно для локального поиска вокруг офсета xref

def read_head_tail(path, n_head=HEAD_READ, n_tail=TAIL_READ):
    with open(path, "rb") as f:
        head = f.read(n_head)
        f.seek(0, 2)
        size = f.tell()
        tail_len = min(n_tail, size)
        f.seek(size - tail_len)
        tail = f.read(tail_len)
    return head, tail, size

def read_chunk(path, offset, length):
    with open(path, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        if offset < 0 or offset >= size:
            return b""
        f.seek(offset)
        return f.read(min(length, size - offset))

def sniff_pdf_version(head):
    # Ожидаем: %PDF-1.4, %PDF-1.7 и т.п. в самом начале
    if not head.startswith(b"%PDF-"):
        return None
    v = head[5:8]  # '1.4', '1.7', иногда '2.0'
    try:
        s = v.decode("ascii", errors="ignore")
        # Бывают расширенные заголовки, попробуем взять до первого нецифро-точечного символа
        s2 = []
        for ch in s:
            if ch.isdigit() or ch == '.':
                s2.append(ch)
            else:
                break
        ver = "".join(s2)
        return ver if ver else None
    except Exception:
        return None

def find_startxref(path, size):
    # Ищем 'startxref' в последних STARTXREF_SCAN байтах
    scan = min(STARTXREF_SCAN, size)
    tail = read_chunk(path, size - scan, scan)
    idx = tail.rfind(b"startxref")
    if idx == -1:
        return False, None
    # после 'startxref' обычно перевод строки и число-офсет
    after = tail[idx + len(b"startxref"): idx + len(b"startxref") + 64]
    # вытащим первое целое число
    num = []
    for ch in after:
        if chr(ch).isdigit():
            num.append(chr(ch))
        elif num:
            break
    try:
        off = int("".join(num)) if num else None
    except Exception:
        off = None
    return True, (off if isinstance(off, int) else None)

def check_xref_at_offset(path, xref_off):
    # Базовая проверка двух вариантов:
    # 1) классический xref: по офсету лежит "xref" (или очень рядом)
    # 2) xref stream: по офсету начинается объект, рядом встречается "/Type /XRef"
    if xref_off is None or xref_off < 0:
        return False, False  # (xref_ok, trailer_present)
    buf = read_chunk(path, max(0, xref_off - 16), NEAR_WINDOW)
    if not buf:
        return False, False

    # Вариант 1: классический xref рядом
    classic = b"xref" in buf[:128]  # обычно ключевое слово в самом начале области
    # Trailer для классики тоже рядом
    has_trailer_kw = b"trailer" in buf

    # Вариант 2: xref stream (может не быть ключевого слова 'xref')
    # Ищем объектный заголовок и /Type /XRef поблизости
    xref_stream = (b"/Type" in buf and b"/XRef" in buf)

    # Для stream-вида ключевого слова trailer может не быть — в этом случае ищем /Root и /ID позже
    xref_ok = classic or xref_stream
    trailer_present = has_trailer_kw  # только для классики; для stream оставим False и проверим поля отдельно
    return xref_ok, trailer_present

def scan_tail_for_keys(path, size, keys=(b"/Root", b"/ID")):
    # Поищем ключи в хвосте файла (часто словарь трейлера/xref stream близко к концу)
    scan = min(TAIL_READ, size)
    tail = read_chunk(path, size - scan, scan)
    found = {k: (k in tail) for k in keys}
    return found

def parse_pdf_features(path):
    head, tail, size = read_head_tail(path)

    # Базовый «магический» заголовок
    pdf_version = sniff_pdf_version(head)

    pdf_startxref_found, xref_off = find_startxref(path, size)
    pdf_xref_ok = False
    pdf_has_trailer = False

    if pdf_startxref_found:
        pdf_xref_ok, trailer_kw = check_xref_at_offset(path, xref_off)
        pdf_has_trailer = bool(trailer_kw)

    # Ищем /Root и /ID в хвосте (работает и для классики, и для xref stream)
    key_flags = scan_tail_for_keys(path, size, keys=(b"/Root", b"/ID"))
    pdf_root_present = bool(key_flags.get(b"/Root", False))
    pdf_ids_present = bool(key_flags.get(b"/ID", False))

    # Сводный признак согласованности трейлера:
    # минимально: найден startxref И (xref ок И (есть trailer-kw ИЛИ есть /Root))
    # для stream-варианта допускаем отсутствие 'trailer', если /Root найден
    pdf_trailer_ok = bool(
        pdf_startxref_found and
        pdf_xref_ok and
        (pdf_has_trailer or pdf_root_present)
    )

    return {
        "pdf_version": pdf_version,                       # str | None
        "pdf_has_trailer": bool(pdf_has_trailer),         # bool
        "pdf_startxref_found": bool(pdf_startxref_found), # bool
        "pdf_xref_ok": bool(pdf_xref_ok),                 # bool
        "pdf_ids_present": bool(pdf_ids_present),         # bool
        "pdf_root_present": bool(pdf_root_present),       # bool
        "pdf_trailer_ok": bool(pdf_trailer_ok),           # bool
    }

def is_pdf_file(head):
    return head.startswith(b"%PDF-")

def main(dir_path):
    rows = []
    files = sorted([os.path.join(dir_path, f) for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))])
    for p in files:
        try:
            head, tail, size = read_head_tail(p, 8, 0)
            if not is_pdf_file(head):
                # пропускаем не-PDF (как и договаривались — парсер формата не запускается на «чужих» файлах)
                continue
            feats = parse_pdf_features(p)
            row = {
                "file": os.path.basename(p),
                "pdf_version": feats["pdf_version"] or "",
                "pdf_has_trailer": int(feats["pdf_has_trailer"]),
                "pdf_startxref_found": int(feats["pdf_startxref_found"]),
                "pdf_xref_ok": int(feats["pdf_xref_ok"]),
                "pdf_ids_present": int(feats["pdf_ids_present"]),
                "pdf_root_present": int(feats["pdf_root_present"]),
                "pdf_trailer_ok": int(feats["pdf_trailer_ok"]),
            }
            rows.append(row)
        except Exception:
            # минимализм: без подробной обработки — просто пропускаем
            pass

    # Печать TSV таблицы
    cols = ["file","pdf_version","pdf_has_trailer","pdf_startxref_found","pdf_xref_ok","pdf_ids_present","pdf_root_present","pdf_trailer_ok"]
    print("\t".join(cols))
    for r in rows:
        print("\t".join(str(r[c]) for c in cols))

if __name__ == "__main__":
    d = sys.argv[1] if len(sys.argv) > 1 else DIR
    main(d)
