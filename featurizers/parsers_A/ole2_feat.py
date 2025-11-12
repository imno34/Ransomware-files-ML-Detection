# parsers_A/ole2_feat.py

import struct

HEADER_SIZE = 512
FREESECT    = 0xFFFFFFFF
ENDOFCHAIN  = 0xFFFFFFFE
FATSECT     = 0xFFFFFFFD
DIFSECT     = 0xFFFFFFFC

DIR_ENTRY_SIZE = 128
MAX_SECTORS_READ = 8192   # предохранитель от зацикливания/повреждений

# Стандартные значения возврата парсера
DEF_RETURN = {
    "ole_dir_ok": False,
    "ole_stream_count": 0,
    "ole_fat_ok": False,
    "ole_mini_fat_ok": False,
    "ole_root_entry_present": False,
    "ole_summaryinfo_present": False,
    "ole_expected_streams_present": False,
    "parser_ok": False,
    "structure_consistent": False
}

#Вспомогательные чтения

def u16(b, off): return struct.unpack_from("<H", b, off)[0]
def u32(b, off): return struct.unpack_from("<I", b, off)[0]

def sector_offset(sector_size, sector_index):
    # Первый сектор начинается сразу после 512-байтового заголовка.
    return HEADER_SIZE + sector_index * sector_size

def read_sector(data: bytes, sector_size: int, sector_index: int) -> bytes:
    off = sector_offset(sector_size, sector_index)
    end = off + sector_size
    if off < 0 or end > len(data): 
        return b""
    return data[off:end]

# Обработка заголовка

def parse_header(data: bytes):
    if len(data) < HEADER_SIZE: 
        return None
    sig = data[:8]
    if sig != b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
        return None

    # корректные смещения согласно спецификации CFB
    sector_shift        = u16(data, 0x1E)            # размер сектора = 1 << sector_shift
    mini_sector_shift   = u16(data, 0x20)
    num_dir_sectors     = u32(data, 0x28)            # часто 0 для версии 3
    num_fat_sectors     = u32(data, 0x2C)
    first_dir_sector    = u32(data, 0x30)
    mini_stream_cutoff  = u32(data, 0x38)            # обычно 4096
    first_minifat       = u32(data, 0x3C)
    num_minifat_sectors = u32(data, 0x40)
    first_difat         = u32(data, 0x44)
    num_difat_sectors   = u32(data, 0x48)
    # DIFAT[109] начинается с 0x4C
    difat0 = struct.unpack_from("<109I", data, 0x4C)

    sector_size = 1 << sector_shift
    mini_sector_size = 1 << mini_sector_shift

    return {
        "sector_size": sector_size,
        "mini_sector_size": mini_sector_size,
        "num_dir_sectors": num_dir_sectors,
        "num_fat_sectors": num_fat_sectors,
        "first_dir_sector": first_dir_sector,
        "mini_stream_cutoff": mini_stream_cutoff,
        "first_minifat": first_minifat,
        "num_minifat_sectors": num_minifat_sectors,
        "first_difat": first_difat,
        "num_difat_sectors": num_difat_sectors,
        "difat0": difat0,
    }

# Сборка FAT из DIFAT

def build_fat(data: bytes, H: dict):
    sector_size = H["sector_size"]
    fat_sector_indices = []

    # 1) DIFAT-индексы из заголовка (109 штук), пропускаем FREESECT, НЕ прерываемся на первом FREESECT
    for s in H["difat0"]:
        if s != FREESECT:
            fat_sector_indices.append(s)

    # 2) Цепочка DIFAT-секторов
    difat_sect = H["first_difat"]
    difat_remaining = H["num_difat_sectors"]
    visited = set()
    while difat_sect not in (FREESECT, ENDOFCHAIN) and difat_remaining > 0 and len(visited) < MAX_SECTORS_READ:
        if difat_sect in visited:
            break
        visited.add(difat_sect)
        buf = read_sector(data, sector_size, difat_sect)
        if len(buf) != sector_size:
            break
        count = (sector_size // 4) - 1
        entries = struct.unpack_from("<%dI" % count, buf, 0)
        for s in entries:
            if s != FREESECT:
                fat_sector_indices.append(s)
        difat_sect = u32(buf, sector_size - 4)
        difat_remaining -= 1

    # 3) Чтение FAT-секторов (каждый — массив u32 ссылок)
    fat = []
    fat_ok = True
    for sidx in fat_sector_indices:
        sbuf = read_sector(data, sector_size, sidx)
        if len(sbuf) != sector_size:
            fat_ok = False
            break
        cnt = sector_size // 4
        fat.extend(struct.unpack_from("<%dI" % cnt, sbuf, 0))

    if not fat:
        fat_ok = False
    return fat, fat_ok

# Чтение цепочки секторов по FAT
# Возвращает конкатенацию секторов по цепочке FAT начиная с 'start' до ENDOFCHAIN
def follow_chain(data: bytes, sector_size: int, fat: list[int], start: int) -> bytes:
    if start in (FREESECT, ENDOFCHAIN):
        return b""
    out = bytearray()
    seen = set()
    cur = start
    hops = 0
    while cur not in (FREESECT, ENDOFCHAIN) and hops < MAX_SECTORS_READ:
        if cur in seen or cur >= len(fat):
            break
        seen.add(cur)
        sec = read_sector(data, sector_size, cur)
        if len(sec) != sector_size:
            break
        out.extend(sec)
        nxt = fat[cur]
        cur = nxt
        hops += 1
    return bytes(out)

# Парсинг потока директорий
def parse_directory_stream(dir_bytes: bytes):
    if len(dir_bytes) < DIR_ENTRY_SIZE:
        return False, 0, False, False, False

    stream_count = 0
    root_present = False
    summaryinfo_present = False
    expected_present = False

    n_entries = len(dir_bytes) // DIR_ENTRY_SIZE
    for i in range(n_entries):
        entry = dir_bytes[i*DIR_ENTRY_SIZE:(i+1)*DIR_ENTRY_SIZE]
        if len(entry) != DIR_ENTRY_SIZE:
            break

        # Name: 128 байт (64 UTF-16LE символов)
        name_raw = entry[:128]
        name_len = u16(entry, 0x40)  # в байтах, включая завершающий нуль
        # Нормализация длины
        if name_len > 128:
            name_len = 128
        if name_len % 2 == 1:
            name_len -= 1
        if name_len < 0:
            name_len = 0

        obj_type = entry[0x42]  # 0=unused,1=storage,2=stream,5=root storage
        if obj_type not in (0, 1, 2, 5):
            return False, stream_count, root_present, summaryinfo_present, expected_present

        if obj_type == 5:
            root_present = True
        if obj_type == 2:
            stream_count += 1

        name = ""
        if name_len > 0:
            try:
                name = name_raw[:name_len].decode("utf-16le", errors="ignore").rstrip("\x00")
            except Exception:
                name = ""

        if name == "\x05SummaryInformation":
            summaryinfo_present = True
        if name in ("WordDocument", "Workbook", "PowerPoint Document"):
            expected_present = True

    return True, stream_count, root_present, summaryinfo_present, expected_present

# Признаки MiniFAT

def mini_fat_ok(data: bytes, H: dict, fat: list[int]) -> bool:
    # Если MiniFAT отсутствует — считаем OK.
    if H["num_minifat_sectors"] == 0 or H["first_minifat"] in (FREESECT, ENDOFCHAIN):
        return True
    # Попробуем прочитать хотя бы первый сектор MiniFAT по индексу first_minifat
    sector_size = H["sector_size"]
    buf = read_sector(data, sector_size, H["first_minifat"])
    if len(buf) != sector_size or (len(buf) % 4) != 0:
        return False
    return True

# Основная логика для одного файла

def parse_ole2(path: str) -> dict:
    try:
        with open(path, "rb") as f:
            data = f.read()

        H = parse_header(data)
        if H is None:
            return None  # не OLE2/CFB

        fat, fat_ok = build_fat(data, H)

        # Поток директорий
        dir_stream = follow_chain(data, H["sector_size"], fat, H["first_dir_sector"])
        ole_dir_ok, ole_stream_count, ole_root_entry_present, ole_summaryinfo_present, ole_expected_streams_present = \
            parse_directory_stream(dir_stream)

        # MiniFAT
        ole_mini_fat_ok = mini_fat_ok(data, H, fat)

        # Расчет сводных булевых признаков
        parser_ok = ole_dir_ok and ole_root_entry_present and fat_ok and (ole_stream_count >=1)
        structure_consistent = parser_ok and (ole_expected_streams_present or ole_summaryinfo_present) and (ole_mini_fat_ok or ole_stream_count <=1)

        return {
            "ole_dir_ok": bool(ole_dir_ok),
            "ole_stream_count": int(ole_stream_count),
            "ole_fat_ok": bool(fat_ok),
            "ole_mini_fat_ok": bool(ole_mini_fat_ok),
            "ole_root_entry_present": bool(ole_root_entry_present),
            "ole_summaryinfo_present": bool(ole_summaryinfo_present),
            "ole_expected_streams_present": bool(ole_expected_streams_present),
            "parser_ok": bool(parser_ok),
            "structure_consistent": bool(structure_consistent)
        }
    except Exception:
        return DEF_RETURN.copy()

