# parsers_B/zip_feat_enc.py

import struct
import zipfile
from typing import Optional, Dict

# Стандартные значения возврата парсера
DEF_RETURN = {
    "zip_any_entry_encrypted": False,
    "zip_encryption_method": "",
    "zip_all_headers_encrypted": False,
    }

def is_encrypted(info: zipfile.ZipInfo) -> bool:
    # Bit 0 в General Purpose Bit Flag = шифрование записи
    # В CPython поле называется .flag_bits
    return bool(info.flag_bits & 0x0001)

def has_aes_extra(info: zipfile.ZipInfo) -> bool:
    # Ищем extra-record с HeaderID = 0x9901 (AES)
    data = info.extra or b""
    i = 0
    n = len(data)
    while i + 4 <= n:
        header_id, sz = struct.unpack_from("<HH", data, i)
        i += 4
        if i + sz > n:
            break
        if header_id == 0x9901:
            return True
        i += sz
    return False

def entry_enc_method(info: zipfile.ZipInfo) -> Optional[str]:
    if not is_encrypted(info):
        return None
    if has_aes_extra(info):
        return "AES"
    return "ZipCrypto"

def parse_zip_enc(path: str) -> Dict:

    any_enc = False
    all_enc = True
    method: Optional[str] = None
    methods_seen = set()

    try:
        with zipfile.ZipFile(path, "r") as zf:
            infos = zf.infolist()
            if not infos:
                # пустой архив
                return DEF_RETURN.copy()

            for info in infos:
                enc = is_encrypted(info)
                any_enc = any_enc or enc
                all_enc = all_enc and enc
                m = entry_enc_method(info)
                if m is not None:
                    methods_seen.add(m)

            if not any_enc:
                method = None
                all_enc = False
            else:
                if len(methods_seen) == 0:
                    # Защищено, но тип не распознан (редко) — считаем ZipCrypto по умолчанию
                    method = "ZipCrypto"
                elif len(methods_seen) == 1:
                    method = next(iter(methods_seen))
                else:
                    method = "Mixed"

            return {
                "zip_any_entry_encrypted": bool(any_enc),
                "zip_encryption_method": method,
                "zip_all_headers_encrypted": bool(all_enc),
            }

    except Exception:
        return DEF_RETURN.copy()
