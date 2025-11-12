#parsers_A/gzip_feat.py

import struct

# ID1, ID2 - это магические байты GZIP
_ID1 = 0x1F
_ID2 = 0x8B
# CM_DEFLATE (8) - 8 соответствует методу DEFLATE
_CM_DEFLATE = 8

# Определяем биты для поля флагов (FLG)
_FHCRC   = 0x02  # Флаг: присутствует CRC16 заголовка
_FEXTRA  = 0x04  # Флаг: присутствуют дополнительные поля
_FNAME   = 0x08  # Флаг: присутствует имя файла
_FCOMMENT= 0x10 # Флаг: присутствует комментарий

# Минимальная длина базового заголовка GZIP (10 байт)
_BASE_HDR_LEN = 10
# Ограничиваем чтение файла первыми 64 КБ, так как вся нужная информация находится в заголовке
_MAX_READ = 64 * 1024

# Словарь с результатами по умолчанию
DEF_RETURN = {
    "gzip_header_ok": False,
    "gzip_mtime_present": False,
    "gzip_name_present": False,
    "parser_ok": False,
    "structure_consistent": False,
}

# Главная функция парсера GZIP
def parse_gzip(path: str) -> dict:
    try:
        # Чтение заголовка
        with open(path, "rb") as f:
            data = f.read(_MAX_READ)

        # Если файл меньше минимальной длины заголовка, программа завершается с результатами по умолчанию
        if len(data) < _BASE_HDR_LEN:
            return DEF_RETURN.copy()

        # Извлечение базовых полей заголовка
        id1, id2, cm, flg = data[0], data[1], data[2], data[3]
        # Проверка магических байтов и метода сжатия
        header_ok = (id1 == _ID1 and id2 == _ID2 and cm == _CM_DEFLATE)

        # Чтение MTIME
        try:
            mtime = struct.unpack_from("<I", data, 4)[0]
        except Exception:
            mtime = 0  # Если не удалось прочитать, считаем 0
        mtime_present = bool(mtime != 0)

        # Поиск необязательных полей после базового заголовка
        pos = _BASE_HDR_LEN
        n = len(data)

        # Если установлен флаг FEXTRA, необходим сдвиг на длину дополнительных полей
        if flg & _FEXTRA:
            if pos + 2 > n:  # Проверка, что в файле достаточно байт для чтения длины
                return {
                    "gzip_header_ok": bool(header_ok),
                    "gzip_mtime_present": bool(mtime_present),
                    "gzip_name_present": False,
                    "parser_ok": bool(header_ok),
                    "structure_consistent": bool(header_ok),
                }
            # Чтение длины дополнительны полей
            xlen = struct.unpack_from("<H", data, pos)[0]
            # Перемещаем указатель в соответствии со сдвигом
            pos += 2 + xlen
            if pos > n:  # Проверка, что не вышли за пределы прочитанных данных
                return {
                    "gzip_header_ok": bool(header_ok),
                    "gzip_mtime_present": bool(mtime_present),
                    "gzip_name_present": False,
                    "parser_ok": bool(header_ok),
                    "structure_consistent": bool(header_ok),
                }

        # Если установлен флаг FNAME, можно считать имя файла
        name_present = False
        if flg & _FNAME:
            start = pos
            # После имени файла всегда идет нулевой байт
            while pos < n and data[pos] != 0:
                pos += 1
            # Если имя непустое (pos > start)
            if pos < n and pos > start:
                name_present = True
            if pos < n:
                pos += 1  # Пропуск завершающего байта

        # Если установлен флаг FCOMMENT, необходим сдвиг на длину комментария
        if flg & _FCOMMENT:
            while pos < n and data[pos] != 0:
                pos += 1
            if pos < n:
                pos += 1

        # Если установлен флаг FHCRC, необходим сдвиг на размер контрольной суммы CRC16
        if flg & _FHCRC:
            pos += 2

        # Возврат итогового словаря признаков
        return {
            "gzip_header_ok": bool(header_ok),
            "gzip_mtime_present": bool(mtime_present),
            "gzip_name_present": bool(name_present),
            "parser_ok": bool(header_ok),
            "structure_consistent": bool(header_ok),
        }
    # Обработчик ошибок
    except Exception:
        return DEF_RETURN.copy()