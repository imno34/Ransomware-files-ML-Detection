import os
from typing import Optional, Tuple

try:
    # py7zr используется только для библиотечной проверки "нужен ли пароль"
    import py7zr
except Exception:
    py7zr = None

# Сигнатура и базовые смещения 7z-контейнера
SEVEN_Z_SIGNATURE = b"\x37\x7A\xBC\xAF\x27\x1C"
SIGNATURE_HEADER_SIZE = 32
NEXT_HEADER_BASE_OFFSET = 32

# Идентификаторы служебных секций (NID) из структуры 7z Header
NID_END = 0x00
NID_HEADER = 0x01
NID_ARCHIVE_PROPERTIES = 0x02
NID_ADDITIONAL_STREAMS_INFO = 0x03
NID_MAIN_STREAMS_INFO = 0x04
NID_FILES_INFO = 0x05
NID_PACK_INFO = 0x06
NID_UNPACK_INFO = 0x07
NID_SUBSTREAMS_INFO = 0x08
NID_SIZE = 0x09
NID_CRC = 0x0A
NID_FOLDER = 0x0B
NID_CODERS_UNPACK_SIZE = 0x0C
NID_NUM_UNPACK_STREAM = 0x0D
NID_ENCODED_HEADER = 0x17

# Method ID для 7z AES-256 + SHA-256 в coder chain
AES_7Z_METHOD_ID = b"\x06\xF1\x07\x01"
MAX_SECTION_ITEMS = 1_000_000

 # Словарь с результатами по умолчанию
DEF_RETURN = {
    "7zip_needs_password": False,
    "7zip_aes_method_present": False,
    "7zip_names_hidden_likely": False,
}


# Низкоуровневый ридер для последовательного обхода бинарных секций Next Header
class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read_byte(self) -> int:
        if self.pos >= len(self.data):
            raise ValueError("Unexpected end of data")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_bytes(self, size: int) -> bytes:
        if size < 0:
            raise ValueError("Negative size")
        end = self.pos + size
        if end > len(self.data):
            raise ValueError("Unexpected end of data")
        out = self.data[self.pos:end]
        self.pos = end
        return out

    def read_uint64_7z(self) -> int:
        # 7z uint64: переменная длина с маской в первом байте
        first = self.read_byte()
        mask = 0x80
        value = 0
        for i in range(8):
            if (first & mask) == 0:
                high = first & (mask - 1)
                return value | (high << (8 * i))
            value |= self.read_byte() << (8 * i)
            mask >>= 1
        return value


def _ensure_reasonable_count(value: int, field: str) -> int:
    # Ограничение на счетчики в поврежденных/враждебных файлах
    if value < 0 or value > MAX_SECTION_ITEMS:
        raise ValueError(f"Unreasonable {field}: {value}")
    return value


def _read_bool_vector(reader: _Reader, count: int) -> list[bool]:
    # Формат "AllAreDefined + битовая маска" для CRC/флагов
    count = _ensure_reasonable_count(count, "bool-vector count")
    all_defined = reader.read_byte()
    if all_defined != 0:
        return [True] * count
    packed = reader.read_bytes((count + 7) // 8)
    out: list[bool] = []
    for idx in range(count):
        byte_val = packed[idx // 8]
        bit_pos = 7 - (idx % 8)
        out.append(((byte_val >> bit_pos) & 1) == 1)
    return out


def _skip_digests(reader: _Reader, count: int) -> list[bool]:
    # Пропуск таблицы CRC-значений с возвратом маски defined
    defined = _read_bool_vector(reader, count)
    for present in defined:
        if present:
            reader.read_bytes(4)
    return defined


def _skip_archive_properties(reader: _Reader) -> None:
    # Секции вида: NID + size + payload ... до NID_END
    while True:
        nid = reader.read_byte()
        if nid == NID_END:
            return
        prop_size = reader.read_uint64_7z()
        reader.read_bytes(prop_size)


def _skip_files_info(reader: _Reader) -> None:
    # FilesInfo: пропускаем свойства файлов и внешние ссылки на данные
    _ = reader.read_uint64_7z()  # num_files
    while True:
        prop_type = reader.read_byte()
        if prop_type == NID_END:
            return
        prop_size = reader.read_uint64_7z()
        external = reader.read_byte()
        if external == 0:
            payload_size = prop_size - 1
            if payload_size < 0:
                raise ValueError("Invalid files-info property size")
            reader.read_bytes(payload_size)
        elif external == 1:
            _ = reader.read_uint64_7z()  # data stream index
        else:
            raise ValueError("Invalid external flag in files info")


def _skip_folder(reader: _Reader) -> Tuple[int, int, list[bytes]]:
    # Folder описывает coder chain; здесь же собираем method IDs кодеров
    num_coders = _ensure_reasonable_count(reader.read_uint64_7z(), "num_coders")
    if num_coders <= 0:
        raise ValueError("Invalid number of coders")

    total_in_streams = 0
    total_out_streams = 0
    method_ids: list[bytes] = []

    for _ in range(num_coders):
        main_byte = reader.read_byte()
        method_id_size = main_byte & 0x0F
        is_complex = (main_byte & 0x10) != 0
        has_attributes = (main_byte & 0x20) != 0
        has_more_alternative_methods = (main_byte & 0x80) != 0

        method_id = reader.read_bytes(method_id_size)
        method_ids.append(method_id)

        if is_complex:
            in_streams = _ensure_reasonable_count(reader.read_uint64_7z(), "in_streams")
            out_streams = _ensure_reasonable_count(reader.read_uint64_7z(), "out_streams")
        else:
            in_streams = 1
            out_streams = 1

        total_in_streams += in_streams
        total_out_streams += out_streams

        if has_attributes:
            props_size = reader.read_uint64_7z()
            reader.read_bytes(props_size)

        if has_more_alternative_methods:
            raise ValueError("Alternative coder methods are not supported")

    bind_pairs = total_out_streams - 1
    for _ in range(bind_pairs):
        _ = reader.read_uint64_7z()
        _ = reader.read_uint64_7z()

    packed_streams = total_in_streams - bind_pairs
    if packed_streams > 1:
        for _ in range(packed_streams):
            _ = reader.read_uint64_7z()

    return total_in_streams, total_out_streams, method_ids


def _skip_pack_info(reader: _Reader) -> None:
    # PackInfo: размеры/CRC упакованных потоков
    _ = reader.read_uint64_7z()  # pack_pos
    num_pack_streams = _ensure_reasonable_count(
        reader.read_uint64_7z(),
        "num_pack_streams",
    )
    while True:
        nid = reader.read_byte()
        if nid == NID_END:
            return
        if nid == NID_SIZE:
            for _ in range(num_pack_streams):
                _ = reader.read_uint64_7z()
        elif nid == NID_CRC:
            _skip_digests(reader, num_pack_streams)
        else:
            raise ValueError("Unknown pack-info sub-block")


def _parse_unpack_info(reader: _Reader) -> Tuple[int, list[bool], list[bytes]]:
    # UnpackInfo: папки (Folders), параметры кодеров и CRC папок
    num_folders: int | None = None
    total_out_streams: int | None = None
    folder_crc_defined: list[bool] | None = None
    method_ids: list[bytes] = []

    while True:
        nid = reader.read_byte()
        if nid == NID_END:
            if num_folders is None:
                raise ValueError("Unpack info does not contain folders")
            if folder_crc_defined is None:
                folder_crc_defined = [False] * num_folders
            return num_folders, folder_crc_defined, method_ids

        if nid == NID_FOLDER:
            num_folders = _ensure_reasonable_count(reader.read_uint64_7z(), "num_folders")
            external = reader.read_byte()
            if external != 0:
                raise ValueError("External folders are not supported")
            total_out_streams = 0
            for _ in range(num_folders):
                _total_in, folder_out, folder_methods = _skip_folder(reader)
                total_out_streams += folder_out
                method_ids.extend(folder_methods)
        elif nid == NID_CODERS_UNPACK_SIZE:
            if total_out_streams is None:
                raise ValueError("Coders unpack size appears before folders")
            for _ in range(total_out_streams):
                _ = reader.read_uint64_7z()
        elif nid == NID_CRC:
            if num_folders is None:
                raise ValueError("CRC appears before folders")
            folder_crc_defined = _skip_digests(reader, num_folders)
        else:
            raise ValueError("Unknown unpack-info sub-block")


def _skip_substreams_info(reader: _Reader, num_folders: int, folder_crc_defined: list[bool]) -> None:
    # SubStreamsInfo: количество под-потоков, размеры и CRC
    if num_folders <= 0:
        raise ValueError("Invalid folders count for substreams info")

    num_unpack_streams = [1] * num_folders
    while True:
        nid = reader.read_byte()
        if nid == NID_END:
            return
        if nid == NID_NUM_UNPACK_STREAM:
            num_unpack_streams = []
            for _ in range(num_folders):
                num_unpack_streams.append(
                    _ensure_reasonable_count(
                        reader.read_uint64_7z(),
                        "num_unpack_streams_per_folder",
                    )
                )
        elif nid == NID_SIZE:
            num_sizes = 0
            for count in num_unpack_streams:
                if count > 0:
                    num_sizes += count - 1
            for _ in range(num_sizes):
                _ = reader.read_uint64_7z()
        elif nid == NID_CRC:
            digests_to_read = 0
            for idx in range(num_folders):
                substreams_count = num_unpack_streams[idx]
                base_crc_defined = folder_crc_defined[idx] if idx < len(folder_crc_defined) else False
                if substreams_count != 1 or not base_crc_defined:
                    digests_to_read += substreams_count
            _skip_digests(reader, digests_to_read)
        else:
            raise ValueError("Unknown substreams-info sub-block")


def _parse_streams_info(reader: _Reader) -> list[bytes]:
    # StreamsInfo-обертка: агрегирует method IDs из UnpackInfo/Folders
    num_folders: int | None = None
    folder_crc_defined: list[bool] = []
    method_ids: list[bytes] = []

    while True:
        nid = reader.read_byte()
        if nid == NID_END:
            return method_ids
        if nid == NID_PACK_INFO:
            _skip_pack_info(reader)
        elif nid == NID_UNPACK_INFO:
            num_folders, folder_crc_defined, unpack_methods = _parse_unpack_info(reader)
            method_ids.extend(unpack_methods)
        elif nid == NID_SUBSTREAMS_INFO:
            if num_folders is None:
                raise ValueError("Substreams info appears before unpack info")
            _skip_substreams_info(reader, num_folders, folder_crc_defined)
        else:
            raise ValueError("Unknown streams-info block")


def _extract_method_ids_from_raw_header(next_header: bytes) -> list[bytes]:
    # Вариант Next Header = Header (0x01)
    reader = _Reader(next_header)
    if reader.read_byte() != NID_HEADER:
        return []

    method_ids: list[bytes] = []
    while True:
        nid = reader.read_byte()
        if nid == NID_END:
            break
        if nid == NID_ARCHIVE_PROPERTIES:
            _skip_archive_properties(reader)
        elif nid == NID_ADDITIONAL_STREAMS_INFO:
            method_ids.extend(_parse_streams_info(reader))
        elif nid == NID_MAIN_STREAMS_INFO:
            method_ids.extend(_parse_streams_info(reader))
        elif nid == NID_FILES_INFO:
            _skip_files_info(reader)
        else:
            break
    return method_ids


def _extract_method_ids_from_encoded_header(next_header: bytes) -> list[bytes]:
    # Вариант Next Header = EncodedHeader (0x17)
    reader = _Reader(next_header)
    if reader.read_byte() != NID_ENCODED_HEADER:
        return []
    return _parse_streams_info(reader)


def _load_next_header(path: str) -> Tuple[bytes, Optional[int]]:
    # Читает SignatureHeader, валидирует границы и возвращает raw Next Header + первый marker
    file_size = os.path.getsize(path)
    if file_size < SIGNATURE_HEADER_SIZE:
        return b"", None

    with open(path, "rb") as fh:
        signature_header = fh.read(SIGNATURE_HEADER_SIZE)
        if len(signature_header) < SIGNATURE_HEADER_SIZE:
            return b"", None
        if signature_header[:6] != SEVEN_Z_SIGNATURE:
            return b"", None

        next_header_offset = int.from_bytes(signature_header[12:20], "little", signed=False)
        next_header_size = int.from_bytes(signature_header[20:28], "little", signed=False)
        if next_header_size <= 0:
            return b"", None

        next_header_start = NEXT_HEADER_BASE_OFFSET + next_header_offset
        next_header_end = next_header_start + next_header_size
        if next_header_start < NEXT_HEADER_BASE_OFFSET or next_header_end > file_size:
            return b"", None

        fh.seek(next_header_start)
        next_header = fh.read(next_header_size)
        if len(next_header) != next_header_size:
            return b"", None

    marker = next_header[0] if next_header else None
    return next_header, marker


def _probe_password_state_with_library(path: str) -> Tuple[bool, bool]:
    # Библиотечная проверка:
    # - needs_password: архив требует пароль для доступа к данным
    # - names_accessible: можно ли получить список имен без пароля
    if py7zr is None:
        return False, False

    needs_password = False
    names_accessible = False

    try:
        with py7zr.SevenZipFile(path, mode="r") as archive:
            probe = getattr(archive, "needs_password", None)
            if callable(probe):
                needs_password = bool(probe())
            elif probe is not None:
                needs_password = bool(probe)
            else:
                needs_password = bool(getattr(archive, "password_protected", False))

            try:
                names = archive.getnames()
                names_accessible = isinstance(names, list)
            except Exception:
                names_accessible = False
    except Exception as exc:
        msg = f"{exc.__class__.__name__} {str(exc)}".lower()
        if "password" in msg:
            needs_password = True
        names_accessible = False

    return needs_password, names_accessible


def _parse_7zip_enc_impl(path: str) -> dict:
    # Чтение Next Header и первичного marker
    next_header, marker = _load_next_header(path)

    # Извлечение coder method IDs для поиска AES
    method_ids: list[bytes] = []
    if next_header:
        try:
            if marker == NID_HEADER:
                method_ids = _extract_method_ids_from_raw_header(next_header)
            elif marker == NID_ENCODED_HEADER:
                method_ids = _extract_method_ids_from_encoded_header(next_header)
        except Exception:
            method_ids = []

    # Признаки шифрования: AES в coder chain + необходимость пароля
    aes_method_present = any(method_id == AES_7Z_METHOD_ID for method_id in method_ids)
    needs_password, names_accessible = _probe_password_state_with_library(path)

    # Если нужен пароль и имена не читаются без пароля, считаем признак истинным
    names_hidden_likely = bool(needs_password and not names_accessible)

    return {
        "7zip_needs_password": bool(needs_password),
        "7zip_aes_method_present": bool(aes_method_present),
        "7zip_names_hidden_likely": bool(names_hidden_likely),
    }


def parse_7zip_enc(path: str) -> dict:
    # Обработка ошибок
    try:
        return _parse_7zip_enc_impl(path)
    except Exception:
        return DEF_RETURN.copy()
