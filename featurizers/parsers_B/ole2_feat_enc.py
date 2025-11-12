# parsers_B/ole2_feat_enc.py

from typing import Optional, Dict, List, Tuple
import olefile
import re

# Объем чтения потоков для эвристик (байт)
PROBE_LEN = 16384

# Набор строк (ASCII) для определения legacy-провайдеров RC4/CryptoAPI
PROVIDER_HINTS_ASCII = [
    b"Microsoft Enhanced Cryptographic Provider",
    b"Microsoft Base Cryptographic Provider",
    b"Microsoft Strong Cryptographic Provider",
    b"Microsoft Enhanced RSA and AES Cryptographic Provider",
]
# Те же строки в UTF-16LE
PROVIDER_HINTS_UTF16 = [s.decode("ascii").encode("utf-16le") for s in PROVIDER_HINTS_ASCII]

# Словарь с результатами по умолчанию
DEF_RETURN = {
    "encrypted_package_present": False,
    "ooxml_encryption_info_present": False,
    "ooxml_encryption_type": "",
    "ole_crypto_provider": "",
    "ole_rc4_meta_present": False,
    "ole_rc4_triplet_present": False,
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

# Попытка извлечения имени legacy-криптопровайдера (ASCII или UTF-16LE)
def detect_legacy_provider(blob: bytes) -> Optional[str]:
    if not blob:
        return None
    # Поиск по известным ASCII-строкам
    for pat in PROVIDER_HINTS_ASCII:
        if blob.find(pat) != -1:
            return pat.decode("ascii", "ignore")
    # Поиск по известным UTF-16LE-строкам
    for pat in PROVIDER_HINTS_UTF16:
        if blob.find(pat) != -1:
            try:
                return pat.decode("utf-16le", "ignore")
            except Exception:
                return None
    # Поиск общих шаблонов "Microsoft ... Cryptographic Provider" (ASCII)
    m = re.search(br"Microsoft[^\x00\r\n]{0,64}Cryptographic Provider[^\x00\r\n]{0,32}", blob)
    if m:
        try:
            return m.group(0).decode("ascii", "ignore")
        except Exception:
            pass
    # Поиск общих шаблонов "Microsoft ... Cryptographic Provider" (UTF-16LE)
    try:
        u = blob.decode("utf-16le", "ignore")
        m2 = re.search(r"Microsoft.{0,64}Cryptographic Provider.{0,32}", u)
        if m2:
            return m2.group(0)
    except Exception:
        pass
    return None

# Грубая проверка наличия BIFF-записи FILEPASS (0x002F) в потоках Excel (обычно 'Workbook'/'Book')
def has_biff_filepass(blob: bytes) -> bool:
    if not blob or len(blob) < 4:
        return False
    # Поиск 0x2F 0x00 (Little Endian)
    return blob.find(b"\x2F\x00") != -1

# Поиск текстовых маркеров 'DocumentEncryption' / 'Encryption' в начале потока PowerPoint
def has_ppt_enc_marker(blob: bytes) -> bool:
    if not blob:
        return False
    if b"DocumentEncryption" in blob or b"Encryption" in blob:
        return True
    try:
        u = blob.decode("utf-16le", "ignore")
        return ("DocumentEncryption" in u) or ("Encryption" in u)
    except Exception:
        return False
# Поиск тройки CryptoAPI (Salt, Verifier, VerifierHash)
def has_rc4_triplet(blob: bytes) -> bool:
    if not blob or len(blob) < 48:
        return False

    def is_triplet_at(i: int) -> bool:
        # Вариант 1: без префиксов длины (16+16+16 байт подряд)
        if i + 48 <= len(blob):
            return True
        return False

    if len(blob) >= 48:
        # Проверка наличия 48 байт в окне 4096 байт с шагом 4
        step = 4
        for i in range(0, min(len(blob) - 48, 4096), step):
            if is_triplet_at(i):
                return True

    # Вариант 2: с LE-префиксами длины (0x10 0x00 0x00 0x00) перед каждым блоком
    pat = b"\x10\x00\x00\x00"  # Длина 16 (LE)
    # Поиск трех вхождений с интервалом 20 байт (4 байта длина + 16 байт данные)
    for i in range(0, min(len(blob) - (3 * (4 + 16)), 8192)):
        if (blob[i:i+4] == pat and
            blob[i+20:i+24] == pat and
            blob[i+40:i+44] == pat):
            return True

    return False

# Главная функция обработчика
def parse_ole2_enc(path: str) -> Dict:
    enc_pkg = False
    enc_info = False
    enc_type: Optional[str] = None
    ole_provider: Optional[str] = None

    ole_rc4_meta_present = False
    ole_rc4_triplet_present = False

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

            # Поиск маркеров шифрования RC4/CryptoAPI

            # 1) Для Excel: поиск FILEPASS (0x002F) в потоке 'Workbook'/'Book'
            for cand in ('Workbook', 'Book'):
                s = find_stream_ci(streams_lower, cand)
                if s:
                    blob = read_probe(ole, lower_map, s)
                    if has_biff_filepass(blob):
                        ole_rc4_meta_present = True
                        # Поиск имени криптопровайдера в том же потоке
                        prov = detect_legacy_provider(blob)
                        if prov:
                            ole_provider = prov
                        break

            # 2) Для PowerPoint: поиск текстовых маркеров в 'PowerPoint Document'
            if not ole_rc4_meta_present:
                s = find_stream_ci(streams_lower, 'PowerPoint Document')
                if s:
                    blob = read_probe(ole, lower_map, s)
                    if has_ppt_enc_marker(blob):
                        ole_rc4_meta_present = True
                        prov = detect_legacy_provider(blob)
                        if prov:
                            ole_provider = prov

            # 3) Для Word/Общий случай: поиск провайдера в 'WordDocument'
            if not ole_rc4_meta_present:
                for cand in ('WordDocument',):
                    s = find_stream_ci(streams_lower, cand)
                    if s:
                        blob = read_probe(ole, lower_map, s)
                        prov = detect_legacy_provider(blob)
                        if prov:
                            ole_provider = prov
                            ole_rc4_meta_present = True
                            break

            # Поиск тройки RC4/CryptoAPI в основных потоках
            if not ole_rc4_triplet_present:
                for cand in ('WordDocument', 'Workbook', 'Book', 'PowerPoint Document'):
                    s = find_stream_ci(streams_lower, cand)
                    if not s:
                        continue
                    blob = read_probe(ole, lower_map, s)
                    if has_rc4_triplet(blob):
                        ole_rc4_triplet_present = True
                        break

        # Возврат словаря признаков
        return {
            "encrypted_package_present": bool(enc_pkg),
            "ooxml_encryption_info_present": bool(enc_info),
            "ooxml_encryption_type": enc_type,
            "ole_crypto_provider": ole_provider,
            "ole_rc4_meta_present": bool(ole_rc4_meta_present),
            "ole_rc4_triplet_present": bool(ole_rc4_triplet_present),
        }
    # Обработка ошибок (например, не OLE2-файл)
    except Exception:
        return DEF_RETURN.copy()