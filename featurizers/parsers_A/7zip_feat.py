# parsers_A/7zip_feat.py
import os
import zlib

# Сигнатура и базовые смещения 7z-контейнера
SEVEN_Z_SIGNATURE = b"\x37\x7A\xBC\xAF\x27\x1C"
SIGNATURE_HEADER_SIZE = 32
NEXT_HEADER_BASE_OFFSET = 32

# Идентификаторы секций (NID) внутри служебного Header 7z
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

# Ограничение на счетчики, чтобы не уходить в OOM/бесконечный разбор на битых файлах
MAX_SECTION_ITEMS = 1_000_000

# Словарь с результатами по умолчанию
DEF_RETURN = {
    "7zip_start_header_crc_valid": False,
    "7zip_next_header_layout_valid": False,
    "7zip_next_header_crc_valid": False,
    "7zip_header_marker_valid": False,
    "7zip_header_sections_valid": False,
    "parser_ok": False,
    "structure_consistent": False,
}


# Низкоуровневый ридер бинарных секций Next Header
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
        # 7z UInt64 кодируется переменной длиной, где первый байт содержит маску
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


def _crc32(data: bytes) -> int:
    # CRC32 приводим к беззнаковому 32-битному диапазону
    return zlib.crc32(data) & 0xFFFFFFFF


def _ensure_reasonable_count(value: int, field: str) -> int:
    # Защита от аномально больших значений в поврежденных контейнерах
    if value < 0 or value > MAX_SECTION_ITEMS:
        raise ValueError(f"Unreasonable {field}: {value}")
    return value


def _read_bool_vector(reader: _Reader, count: int) -> list[bool]:
    # Формат 7z: AllAreDefined + битовая маска флагов
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
    # Пропуск CRC-таблицы с возвратом маски "у каких объектов CRC задан"
    defined = _read_bool_vector(reader, count)
    for present in defined:
        if present:
            reader.read_bytes(4)
    return defined


def _skip_archive_properties(reader: _Reader) -> None:
    # ArchiveProperties: набор пар NID + size + payload до NID_END
    while True:
        nid = reader.read_byte()
        if nid == NID_END:
            return
        prop_size = reader.read_uint64_7z()
        reader.read_bytes(prop_size)


def _skip_files_info(reader: _Reader) -> None:
    # FilesInfo: пропуск секции свойств файлов без детального декодирования имен/атрибутов
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


def _skip_folder(reader: _Reader) -> int:
    # Folder: описание coder chain (кодеки, bind pairs, packed streams)
    num_coders = _ensure_reasonable_count(reader.read_uint64_7z(), "num_coders")
    if num_coders <= 0:
        raise ValueError("Invalid number of coders")

    total_in_streams = 0
    total_out_streams = 0
    for _ in range(num_coders):
        main_byte = reader.read_byte()
        method_id_size = main_byte & 0x0F
        is_complex = (main_byte & 0x10) != 0
        has_attributes = (main_byte & 0x20) != 0
        has_more_alternative_methods = (main_byte & 0x80) != 0

        reader.read_bytes(method_id_size)
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

    if total_in_streams <= 0 or total_out_streams <= 0:
        raise ValueError("Invalid folder stream topology")

    bind_pairs = total_out_streams - 1
    for _ in range(bind_pairs):
        _ = reader.read_uint64_7z()
        _ = reader.read_uint64_7z()

    packed_streams = total_in_streams - bind_pairs
    if packed_streams < 0:
        raise ValueError("Invalid packed streams count")
    if packed_streams > 1:
        for _ in range(packed_streams):
            _ = reader.read_uint64_7z()

    return total_out_streams


def _skip_pack_info(reader: _Reader) -> None:
    # PackInfo: размеры и CRC упакованных потоков
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


def _skip_unpack_info(reader: _Reader) -> tuple[int, list[bool]]:
    # UnpackInfo: набор folders, unpack sizes и CRC папок
    num_folders: int | None = None
    total_out_streams: int | None = None
    folder_crc_defined: list[bool] | None = None

    while True:
        nid = reader.read_byte()
        if nid == NID_END:
            if num_folders is None:
                raise ValueError("Unpack info does not contain folders")
            if folder_crc_defined is None:
                folder_crc_defined = [False] * num_folders
            return num_folders, folder_crc_defined

        if nid == NID_FOLDER:
            num_folders = _ensure_reasonable_count(reader.read_uint64_7z(), "num_folders")
            external = reader.read_byte()
            if external != 0:
                raise ValueError("External folders are not supported")
            total_out_streams = 0
            for _ in range(num_folders):
                total_out_streams += _skip_folder(reader)
        elif nid == NID_CODERS_UNPACK_SIZE:
            if total_out_streams is None:
                raise ValueError("Coders unpack size appears before folders")
            _ensure_reasonable_count(total_out_streams, "coders_unpack_size_count")
            for _ in range(total_out_streams):
                _ = reader.read_uint64_7z()
        elif nid == NID_CRC:
            if num_folders is None:
                raise ValueError("CRC appears before folders")
            folder_crc_defined = _skip_digests(reader, num_folders)
        else:
            raise ValueError("Unknown unpack-info sub-block")


def _skip_substreams_info(reader: _Reader, num_folders: int, folder_crc_defined: list[bool]) -> None:
    # SubStreamsInfo: количество подпотоков, их размеры и CRC
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
            _ensure_reasonable_count(digests_to_read, "substreams_crc_digests")
            _skip_digests(reader, digests_to_read)
        else:
            raise ValueError("Unknown substreams-info sub-block")


def _skip_streams_info(reader: _Reader) -> tuple[bool, bool, bool]:
    # Обход оболочки StreamsInfo с фиксацией, какие подподразделы реально встретились
    num_folders: int | None = None
    folder_crc_defined: list[bool] = []
    seen_pack_info = False
    seen_unpack_info = False
    seen_substreams_info = False
    while True:
        nid = reader.read_byte()
        if nid == NID_END:
            return seen_pack_info, seen_unpack_info, seen_substreams_info
        if nid == NID_PACK_INFO:
            _skip_pack_info(reader)
            seen_pack_info = True
        elif nid == NID_UNPACK_INFO:
            num_folders, folder_crc_defined = _skip_unpack_info(reader)
            seen_unpack_info = True
        elif nid == NID_SUBSTREAMS_INFO:
            if num_folders is None:
                raise ValueError("Substreams info appears before unpack info")
            _skip_substreams_info(reader, num_folders, folder_crc_defined)
            seen_substreams_info = True
        else:
            raise ValueError("Unknown streams-info block")


def _validate_header_sections_raw(next_header: bytes) -> bool:
    # Ветка Header (0x01): проверяем каркас raw header и порядок базовых секций
    reader = _Reader(next_header)
    if reader.read_byte() != NID_HEADER:
        return False

    seen_main_streams = False
    seen_files_info = False
    top_level_end_seen = False

    while True:
        nid = reader.read_byte()
        if nid == NID_END:
            top_level_end_seen = True
            break

        if nid == NID_ARCHIVE_PROPERTIES:
            if seen_main_streams or seen_files_info:
                return False
            _skip_archive_properties(reader)
        elif nid == NID_ADDITIONAL_STREAMS_INFO:
            if seen_main_streams or seen_files_info:
                return False
            _skip_streams_info(reader)
        elif nid == NID_MAIN_STREAMS_INFO:
            if seen_main_streams or seen_files_info:
                return False
            seen_pack, seen_unpack, seen_substreams = _skip_streams_info(reader)
            if not (seen_pack or seen_unpack or seen_substreams):
                return False
            seen_main_streams = True
        elif nid == NID_FILES_INFO:
            if not seen_main_streams or seen_files_info:
                return False
            _skip_files_info(reader)
            seen_files_info = True
        else:
            return False

    if not top_level_end_seen or not seen_main_streams or not seen_files_info:
        return False

    if reader.remaining() > 0:
        tail = reader.read_bytes(reader.remaining())
        if any(byte != 0 for byte in tail):
            return False

    return True


def _validate_header_sections_encoded(next_header: bytes) -> bool:
    # Ветка EncodedHeader (0x17): проверяем служебный StreamsInfo-wrapper
    reader = _Reader(next_header)
    if reader.read_byte() != NID_ENCODED_HEADER:
        return False

    seen_pack, seen_unpack, _seen_substreams = _skip_streams_info(reader)
    if not (seen_pack and seen_unpack):
        return False

    if reader.remaining() > 0:
        tail = reader.read_bytes(reader.remaining())
        if any(byte != 0 for byte in tail):
            return False

    return True


def _parse_7zip_impl(path: str) -> dict:
    # Читаем SignatureHeader и валидируем минимальный размер контейнера
    file_size = os.path.getsize(path)
    if file_size < SIGNATURE_HEADER_SIZE:
        return DEF_RETURN.copy()

    with open(path, "rb") as fh:
        signature_header = fh.read(SIGNATURE_HEADER_SIZE)
        if len(signature_header) < SIGNATURE_HEADER_SIZE:
            return DEF_RETURN.copy()

        # Проверка сигнатуры и CRC стартового заголовка (20 байт после поля CRC)
        signature_ok = signature_header[:6] == SEVEN_Z_SIGNATURE
        start_header_crc = int.from_bytes(signature_header[8:12], "little", signed=False)
        start_header_payload = signature_header[12:32]
        start_header_crc_valid = signature_ok and (_crc32(start_header_payload) == start_header_crc)

        next_header_offset = int.from_bytes(signature_header[12:20], "little", signed=False)
        next_header_size = int.from_bytes(signature_header[20:28], "little", signed=False)
        next_header_crc = int.from_bytes(signature_header[28:32], "little", signed=False)

        # Валидация расположения Next Header в пределах файла
        next_header_start = NEXT_HEADER_BASE_OFFSET + next_header_offset
        next_header_end = next_header_start + next_header_size
        next_header_layout_valid = (
            signature_ok
            and next_header_size > 0
            and next_header_start >= NEXT_HEADER_BASE_OFFSET
            and next_header_end <= file_size
        )

        # Проверка CRC Next Header и допустимого marker (Header или EncodedHeader)
        if next_header_layout_valid:
            fh.seek(next_header_start)
            next_header = fh.read(next_header_size)
            if len(next_header) == next_header_size:
                next_header_crc_valid = _crc32(next_header) == next_header_crc
                first_marker = next_header[0] if next_header else None
                header_marker_valid = first_marker in (NID_HEADER, NID_ENCODED_HEADER)
            else:
                next_header_crc_valid = False
                header_marker_valid = False
                first_marker = None
                next_header = b""
        else:
            next_header_crc_valid = False
            header_marker_valid = False
            first_marker = None
            next_header = b""

        # Валидация "каркаса" секций для соответствующего типа header marker
        header_sections_valid = False
        if header_marker_valid:
            try:
                if first_marker == NID_HEADER:
                    header_sections_valid = _validate_header_sections_raw(next_header)
                elif first_marker == NID_ENCODED_HEADER:
                    header_sections_valid = _validate_header_sections_encoded(next_header)
                else:
                    header_sections_valid = False
            except Exception:
                header_sections_valid = False

        # Расчет сводных булевых признаков
        parser_ok = (bool(start_header_crc_valid) and bool(next_header_layout_valid) and bool(header_marker_valid))
        structure_consistent = bool(parser_ok and bool(next_header_crc_valid) and bool(header_sections_valid))

    # Возврат словаря признаков
    return {
        "7zip_start_header_crc_valid": bool(start_header_crc_valid),
        "7zip_next_header_layout_valid": bool(next_header_layout_valid),
        "7zip_next_header_crc_valid": bool(next_header_crc_valid),
        "7zip_header_marker_valid": bool(header_marker_valid),
        "7zip_header_sections_valid": bool(header_sections_valid),
        "parser_ok": bool(parser_ok),
        "structure_consistent": bool(structure_consistent),
    }


def parse_7zip(path: str) -> dict:
    try:
        return _parse_7zip_impl(path)
    
    # Обработка ошибок
    except Exception:
        return DEF_RETURN.copy()
