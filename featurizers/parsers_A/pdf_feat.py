# parsers_A/pdf_feat.py

import os
import math
import re

HEAD_READ = 64 * 1024     # Объем чтения "головы" файла (байт)
TAIL_READ = 128 * 1024    # Объем чтения "хвоста" файла (байт)
STARTXREF_SCAN = 256 * 1024  # Окно сканирования 'startxref' в хвосте файла
NEAR_WINDOW = 4096        # Окно для локального поиска вокруг смещения xref

# Словарь с результатами по умолчанию
DEF_RETURN = {
    "pdf_version": "",
    "pdf_has_trailer": False,
    "pdf_startxref_found": False,
    "pdf_xref_ok": False,
    "pdf_ids_present": False,
    "pdf_root_present": False,
    "pdf_trailer_ok": False,
    "pdf_obj_count_est": 0.0,
    "parser_ok": False,
    "structure_consistent": False,
}
# Чтение заголовка и трейлера
def read_head_tail(path, n_head=HEAD_READ, n_tail=TAIL_READ):
    with open(path, "rb") as f:
        head = f.read(n_head)
        f.seek(0, 2)
        size = f.tell()
        tail_len = min(n_tail, size)
        f.seek(size - tail_len)
        tail = f.read(tail_len)
    return head, tail, size

#Чтение произвольного блока (чанка) данных из файла
def read_chunk(path, offset, length):
    with open(path, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        if offset < 0 or offset >= size:
            return b""
        f.seek(offset)
        return f.read(min(length, size - offset))

# Определение версии PDF (%PDF-X.Y) из заголовка
def sniff_pdf_version(head):
    if not head.startswith(b"%PDF-"):
        return None
    v = head[5:8]  # '1.4', '1.7', '2.0'
    try:
        s = v.decode("ascii", errors="ignore")
        # Обработка расширенных заголовков (извлечение до первого символа не цифры)
        s2 = []
        for ch in s:
            if ch.isdigit() or ch == '.':
                s2.append(ch)
            else:
                break
        ver = "".join(s2)
        ver = float(ver)
        return ver if ver else None
    except Exception:
        return None
#Поиск ключевого слова 'startxref' и смещения таблицы перекрестных ссылок
def find_startxref(path, size):
    scan = min(STARTXREF_SCAN, size)
    tail = read_chunk(path, size - scan, scan)
    idx = tail.rfind(b"startxref")
    if idx == -1:
        return False, None
    # После 'startxref' обычно идет \n и размер смещения
    after = tail[idx + len(b"startxref"): idx + len(b"startxref") + 64]
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

# Проверка наличия таблицы 'xref' (классической или stream) по смещению
def check_xref_at_offset(path, xref_off):
    # Проверка двух вариантов:
    # 1) Классическая: 'xref' по смещению или рядом
    # 2) Потоковая: объект, содержащий /Type /XRef
    if xref_off is None or xref_off < 0:
        return False, False  # (xref_ok, trailer_present)
    buf = read_chunk(path, max(0, xref_off - 16), NEAR_WINDOW)
    if not buf:
        return False, False

    # Классический 'xref' (ключевое слово)
    classic = b"xref" in buf[:128]
    # Классический 'trailer' также должен быть рядом
    has_trailer_kw = b"trailer" in buf

    # Потоковый 'xref' (может не иметь слова 'xref')
    xref_stream = (b"/Type" in buf and b"/XRef" in buf)

    # Для потокового трейлер может отсутствовать
    xref_ok = classic or xref_stream
    trailer_present = has_trailer_kw
    
    # Попытка оценки размера таблицы 'xref' (поля /Size)
    xref_size = None
    try:
        if classic:
            m = re.search(br"xref\s+((?:\d+\s+\d+\s*)+)", buf, re.IGNORECASE)
            if m:
                pairs = re.findall(br"(\d+)\s+(\d+)", m.group(1))
                if pairs:
                    xref_size = sum(int(b) for a, b in pairs)
        elif xref_stream:
            m = re.search(br"/Size\s+(\d+)", buf)
            if m:
                xref_size = int(m.group(1))
    except Exception:
        xref_size = None

    return xref_ok, trailer_present, xref_size

# Сканирование хвоста файла на наличие ключей
def scan_tail_for_keys(path, size, keys=(b"/Root", b"/ID")):
    # Поиск ключей в трейлере
    scan = min(TAIL_READ, size)
    tail = read_chunk(path, size - scan, scan)
    found = {k: (k in tail) for k in keys}
    return found

def parse_pdf_features(path):
    head, tail, size = read_head_tail(path)

    # 1. Проверка сигнатуры и версии
    pdf_version = sniff_pdf_version(head)

    # 2. Поиск 'startxref' и проверка таблицы xref
    pdf_startxref_found, xref_off = find_startxref(path, size)
    pdf_xref_ok = False
    pdf_has_trailer = False
    xref_size = None

    if pdf_startxref_found:
        res = check_xref_at_offset(path, xref_off)
        try:
            # Поддержка возврата 2 или 3 значений
            if isinstance(res, tuple) and len(res) >= 2:
                pdf_xref_ok = bool(res[0])
                pdf_has_trailer = bool(res[1])
                if len(res) >= 3:
                    xref_size = res[2]
        except Exception:
            pass

    # 3. Поиск ключей /Root и /ID в хвосте
    key_flags = scan_tail_for_keys(path, size, keys=(b"/Root", b"/ID"))
    pdf_root_present = bool(key_flags.get(b"/Root", False))
    pdf_ids_present = bool(key_flags.get(b"/ID", False))

    # 4. Расчет сводного признака 'pdf_trailer_ok'
    pdf_trailer_ok = pdf_startxref_found and pdf_xref_ok and (pdf_has_trailer or pdf_root_present)

    # 5. Оценка количества объектов
    def stream_scan_obj_tokens(pth: str, cap: int = 1024):
        try:
            max_bytes = int(cap) * 1024
            total = os.path.getsize(pth)

            # Чтение 'головы'
            head_n = min(max_bytes, total)
            head_buf = b""
            with open(pth, "rb") as f:
                head_buf = f.read(head_n)

            # Чтение 'хвоста'
            tail_n = min(max_bytes, max(0, total - head_n))
            tail_buf = b""
            if tail_n > 0:
                with open(pth, "rb") as f:
                    f.seek(max(0, total - tail_n))
                    tail_buf = f.read(tail_n)

            # Объединение буферов
            combined = head_buf + b"\n" + tail_buf

            # Подсчет вхождений "n 0 obj"
            cnt = len(re.findall(br"\d+\s+0\s+obj", combined))
            capped = bool(total > (len(head_buf) + len(tail_buf)))
            return int(cnt), capped
        except Exception:
            return 0, False

    # Использование оценки из /Size, если доступно, иначе - сканирование
    if pdf_xref_ok and isinstance(xref_size, int) and xref_size > 0:
        obj_count = int(xref_size)
    else:
        scan_cap = max(512, min(4096, size // 4096))
        # stream_scan_obj_tokens возвращает (count, capped_flag)
        obj_count, _capped = stream_scan_obj_tokens(path, cap=scan_cap)
    # Применение логарифма (log1p) для сглаживания
    pdf_obj_count_est = float(math.log1p(max(0, int(obj_count))))

    # 6. Расчет сводных булевых признаков
    parser_ok = bool(((pdf_has_trailer and pdf_startxref_found) or pdf_xref_ok or pdf_trailer_ok))
    structure_consistent = bool((parser_ok and ((pdf_xref_ok and pdf_trailer_ok and pdf_root_present) or (pdf_trailer_ok and pdf_root_present and pdf_ids_present))))

    # 7. Нормализация версии PDF (float или None)
    try:
        pdf_version_val = float(pdf_version) if pdf_version is not None and pdf_version != "" else None
    except Exception:
        pdf_version_val = None

    return {
        "pdf_version": pdf_version_val,
        "pdf_has_trailer": bool(pdf_has_trailer),
        "pdf_startxref_found": bool(pdf_startxref_found),
        "pdf_xref_ok": bool(pdf_xref_ok),
        "pdf_ids_present": bool(pdf_ids_present),
        "pdf_root_present": bool(pdf_root_present),
        "pdf_trailer_ok": bool(pdf_trailer_ok),
        "pdf_obj_count_est": float(pdf_obj_count_est),
        "parser_ok": bool(parser_ok),
        "structure_consistent": bool(structure_consistent)
        }
 # Публичный метод обработчика
def parse_pdf(path: str) -> dict:
    try:
        return parse_pdf_features(path)
    except Exception:
        return DEF_RETURN.copy()
