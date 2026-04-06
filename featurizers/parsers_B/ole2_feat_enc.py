# parsers_B/ole2_feat_enc.py

from typing import Optional, Dict, List, Tuple
import olefile

# Объем чтения потоков для эвристик (байт)
PROBE_LEN = 16384

# Словарь с результатами по умолчанию
DEF_RETURN = {
    "encrypted_package_present": False,
    "ooxml_encryption_info_present": False,
    "ooxml_encryption_type": "",
    "ole_format_family": "",
    "ole_encryption_present": False,
    "ole_encryption_struct_valid": False,
    "ole_write_protection_present": False,
}

# Ф-ция определения типа шифрования
def detect_ooxml_enc_type(blob: bytes) -> Optional[str]:
    if not blob:
        return None
    b = blob.lstrip()
    # Проверка на XML-содержимое
    if b.startswith(b'<?xml') or b.startswith(b'<'):
        # Поиск маркеров Agile-шифрования (стандарт OOXML)
        if (b.find(b'<encryption') != -1 and
            (b.find(b'http://schemas.microsoft.com/office/2006/encryption') != -1 or
             b.find(b'http://schemas.microsoft.com/office/2006/keyEncryptor/password') != -1 or
             b.find(b'keyData') != -1)):
            return 'Agile'
        return 'Extensible'
    # Если не XML, считаем 'Standard' (legacy CryptoAPI)
    return 'Standard'

# Получение списка потоков
def list_streams_ci(ole) -> Tuple[List[str], List[str], Dict[str, str]]:
    orig = ["/".join(p) for p in ole.listdir(streams=True, storages=False)]
    lower_map = {s.lower(): s for s in orig}
    return orig, list(lower_map.keys()), lower_map

# Поиск потока по имени
def find_stream_ci(streams_lower: List[str], target: str) -> Optional[str]:
    t = target.lower()
    for s in streams_lower:
        if s.endswith(t):
            return s
    return None

# Чтение начала потока
def read_probe(ole, lower_to_orig: Dict[str, str], name_lower: str, max_len: int = PROBE_LEN) -> bytes:
    try:
        with ole.openstream(lower_to_orig[name_lower]) as st:
            return st.read(max_len)
    except Exception:
        return b""

# Определение семейства OLE2-формата по характерным потокам
def detect_ole_format_family(streams_lower: List[str]) -> str:
    if find_stream_ci(streams_lower, 'WordDocument'):
        return 'doc'
    if find_stream_ci(streams_lower, 'Workbook') or find_stream_ci(streams_lower, 'Book'):
        return 'xls'
    if find_stream_ci(streams_lower, 'PowerPoint Document'):
        return 'ppt'
    return 'other_ole2'

# Проверка Word (.doc): FIB-флаги + table stream
def analyze_doc_encryption(ole, streams_lower: List[str], lower_map: Dict[str, str]) -> Tuple[bool, bool, bool]:
    s_word = find_stream_ci(streams_lower, 'WordDocument')
    if not s_word:
        return False, False, False

    word_blob = read_probe(ole, lower_map, s_word, max_len=512)
    if len(word_blob) < 18:
        return False, False, False

    try:
        flags = int.from_bytes(word_blob[10:12], 'little')
        lkey = int.from_bytes(word_blob[14:18], 'little')

        # FibBase bitfield
        f_encrypted = bool(flags & 0x0100)
        f_which_tbl = bool(flags & 0x0200)     # 0Table / 1Table
        f_write_reservation = bool(flags & 0x0800)
        f_obfuscated = bool(flags & 0x8000)

        enc_present = f_encrypted
        write_prot = f_write_reservation

        if not enc_present:
            return False, False, write_prot

        # Для XOR-obfuscation считаем структуру валидной по самому факту соответствующего флага
        if f_obfuscated:
            return True, True, write_prot

        # Для normal encryption ожидаем наличие table stream и ненулевой lKey
        table_name = '1Table' if f_which_tbl else '0Table'
        s_table = find_stream_ci(streams_lower, table_name)
        if not s_table or lkey <= 0:
            return True, False, write_prot

        table_blob = read_probe(ole, lower_map, s_table, max_len=max(PROBE_LEN, lkey + 64))
        if len(table_blob) < lkey:
            return True, False, write_prot

        return True, True, write_prot
    except Exception:
        return False, False, False

# Итерация по BIFF-записям Excel (.xls)
def iter_biff_records(blob: bytes):
    if not blob or len(blob) < 4:
        return

    i = 0
    n = len(blob)
    while i + 4 <= n:
        rec_id = int.from_bytes(blob[i:i+2], 'little')
        rec_len = int.from_bytes(blob[i+2:i+4], 'little')
        j = i + 4 + rec_len
        if j > n:
            break
        yield rec_id, blob[i+4:j]
        i = j

# Проверка Excel (.xls): BIFF FilePass / FileSharing
def analyze_xls_encryption(ole, streams_lower: List[str], lower_map: Dict[str, str]) -> Tuple[bool, bool, bool]:
    s_book = None
    for cand in ('Workbook', 'Book'):
        s_book = find_stream_ci(streams_lower, cand)
        if s_book:
            break

    if not s_book:
        return False, False, False

    blob = read_probe(ole, lower_map, s_book)
    if not blob:
        return False, False, False

    enc_present = False
    enc_valid = False
    write_prot = False

    try:
        for rec_id, payload in iter_biff_records(blob):
            # FILEPASS
            if rec_id == 0x002F:
                enc_present = True
                if len(payload) >= 2:
                    enc_valid = True
            # FILESHARING
            elif rec_id == 0x005B:
                write_prot = True
    except Exception:
        return False, False, False

    return enc_present, enc_valid, write_prot

# PowerPoint (.ppt): walk CurrentUserAtom -> UserEditAtom -> PersistDirectoryAtom
# and verify that encryptSessionPersistIdRef resolves to CryptSession10Container.
def analyze_ppt_encryption(ole, streams_lower: List[str], lower_map: Dict[str, str]) -> Tuple[bool, bool, bool]:
    s_current_user = find_stream_ci(streams_lower, 'Current User')
    s_ppt = find_stream_ci(streams_lower, 'PowerPoint Document')

    if not s_current_user or not s_ppt:
        return False, False, False

    current_user_blob = read_probe(ole, lower_map, s_current_user, max_len=64)

    if len(current_user_blob) < 20:
        return False, False, False

    try:
        ppt_name = lower_map[s_ppt]
        ppt_size = ole.get_size(ppt_name)

        def read_ppt_at(offset: int, length: int) -> bytes:
            if offset < 0 or length <= 0 or offset >= ppt_size:
                return b""
            length = min(length, ppt_size - offset)
            try:
                with ole.openstream(ppt_name) as st:
                    st.seek(offset)
                    return st.read(length)
            except Exception:
                return b""

        def parse_persist_dir_atom(offset: int) -> Dict[int, int]:
            hdr = read_ppt_at(offset, 8)
            if len(hdr) < 8:
                return {}

            rec_type = int.from_bytes(hdr[2:4], 'little')
            rec_len = int.from_bytes(hdr[4:8], 'little')
            if rec_type != 0x1772 or rec_len <= 0 or (rec_len % 4) != 0:
                return {}

            payload = read_ppt_at(offset + 8, rec_len)
            if len(payload) < rec_len:
                return {}

            persist_map: Dict[int, int] = {}
            i = 0
            while i + 4 <= len(payload):
                entry = int.from_bytes(payload[i:i+4], 'little')
                i += 4

                persist_id = entry & 0x000FFFFF
                c_persist = (entry >> 20) & 0xFFF
                if c_persist <= 0 or i + (4 * c_persist) > len(payload):
                    return {}

                for j in range(c_persist):
                    obj_off = int.from_bytes(payload[i:i+4], 'little')
                    i += 4
                    persist_map[persist_id + j] = obj_off

            return persist_map

        rec_type = int.from_bytes(current_user_blob[2:4], 'little')
        size = int.from_bytes(current_user_blob[8:12], 'little')
        header_token = int.from_bytes(current_user_blob[12:16], 'little')
        offset_to_current_edit = int.from_bytes(current_user_blob[16:20], 'little')

        # RT_CurrentUserAtom = 0x0FF6
        current_user_ok = (rec_type == 0x0FF6 and size == 0x14)
        if not current_user_ok or not (0 <= offset_to_current_edit < ppt_size):
            return False, False, False

        enc_present = (header_token == 0xF3D1C4DF)
        enc_valid = False

        seen_user_edits = set()
        next_user_edit = offset_to_current_edit
        for _ in range(32):
            if next_user_edit in seen_user_edits or not (0 <= next_user_edit < ppt_size):
                break
            seen_user_edits.add(next_user_edit)

            user_edit = read_ppt_at(next_user_edit, 40)
            if len(user_edit) < 36:
                break

            ue_type = int.from_bytes(user_edit[2:4], 'little')
            ue_len = int.from_bytes(user_edit[4:8], 'little')
            if ue_type != 0x0FF5 or ue_len < 28:
                break

            offset_last_edit = int.from_bytes(user_edit[16:20], 'little')
            offset_persist_directory = int.from_bytes(user_edit[20:24], 'little')
            encrypt_session_pid = (
                int.from_bytes(user_edit[36:40], 'little')
                if ue_len >= 32 and len(user_edit) >= 40 else 0
            )

            if encrypt_session_pid > 0:
                enc_present = True
                persist_map = parse_persist_dir_atom(offset_persist_directory)
                enc_obj_offset = persist_map.get(encrypt_session_pid)
                if enc_obj_offset is not None and 0 <= enc_obj_offset < ppt_size:
                    enc_hdr = read_ppt_at(enc_obj_offset, 8)
                    if len(enc_hdr) >= 8:
                        enc_rec_type = int.from_bytes(enc_hdr[2:4], 'little')
                        enc_rec_len = int.from_bytes(enc_hdr[4:8], 'little')
                        if enc_rec_type == 0x2F14 and enc_rec_len > 0:
                            enc_valid = True
                            break

            if offset_last_edit == 0:
                break
            next_user_edit = offset_last_edit

        write_prot = False
        return enc_present, enc_valid, write_prot

    except Exception:
        return False, False, False

# Главная функция обработчика
def parse_ole2_enc(path: str) -> Dict:
    enc_pkg = False
    enc_info = False
    enc_type: Optional[str] = None

    ole_format_family = ""
    ole_encryption_present = False
    ole_encryption_struct_valid = False
    ole_write_protection_present = False

    try:
        # Чтение OLE-контейнера
        with olefile.OleFileIO(path) as ole:
            orig_streams, streams_lower, lower_map = list_streams_ci(ole)

            # Поиск стандартных потоков шифрования OOXML ('EncryptedPackage', 'EncryptionInfo')
            s_encpkg = find_stream_ci(streams_lower, 'EncryptedPackage')
            s_encinfo = find_stream_ci(streams_lower, 'EncryptionInfo')
            enc_pkg = s_encpkg is not None
            enc_info = s_encinfo is not None

            # Определение типа шифрования OOXML
            if s_encinfo:
                blob = read_probe(ole, lower_map, s_encinfo)
                enc_type = detect_ooxml_enc_type(blob) or 'Unknown'
            if enc_type is None and enc_pkg:
                enc_type = 'Unknown'

            # Определение семейства legacy OLE2
            ole_format_family = detect_ole_format_family(streams_lower)

            # Разбор legacy OLE2-форматов
            if ole_format_family == 'doc':
                (
                    ole_encryption_present,
                    ole_encryption_struct_valid,
                    ole_write_protection_present,
                ) = analyze_doc_encryption(ole, streams_lower, lower_map)

            elif ole_format_family == 'xls':
                (
                    ole_encryption_present,
                    ole_encryption_struct_valid,
                    ole_write_protection_present,
                ) = analyze_xls_encryption(ole, streams_lower, lower_map)

            elif ole_format_family == 'ppt':
                (
                    ole_encryption_present,
                    ole_encryption_struct_valid,
                    ole_write_protection_present,
                ) = analyze_ppt_encryption(ole, streams_lower, lower_map)

        # Возврат словаря признаков
        return {
            "encrypted_package_present": bool(enc_pkg),
            "ooxml_encryption_info_present": bool(enc_info),
            "ooxml_encryption_type": enc_type if enc_type is not None else "",
            "ole_format_family": ole_format_family,
            "ole_encryption_present": bool(ole_encryption_present),
            "ole_encryption_struct_valid": bool(ole_encryption_struct_valid),
            "ole_write_protection_present": bool(ole_write_protection_present),
        }

    # Обработка ошибок (например, не OLE2-файл)
    except Exception:
        return DEF_RETURN.copy()
