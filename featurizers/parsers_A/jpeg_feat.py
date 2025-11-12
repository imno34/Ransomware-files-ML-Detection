#parsers_A/jpeg_feat.py

import struct

# Определение маркеров формата JPEG
SOI = 0xD8  # Маркер начала изображения (Start of Image)
EOI = 0xD9  # Маркер конца изображения (End of Image)
SOS = 0xDA  # Маркер начала скана (Start of Scan)
TEM = 0x01  # Временный маркер (без поля длины)
RST0, RST7 = 0xD0, 0xD7 # Маркеры перезапуска (Restart markers)


# Набор маркеров SOF (Start Of Frame), обозначающих начало кадра
SOF_MARKERS = {
    0xC0, 0xC1, 0xC2, 0xC3,
    0xC5, 0xC6, 0xC7,
    0xC9, 0xCA, 0xCB,
    0xCD, 0xCE, 0xCF
}

# Ограничение на максимальное количество сегментов для предотвращения зацикливания и чтения слишком больших файлов
MAX_SEGMENTS = 200000

# Словарь с результатами по умолчанию
DEF_RETURN = {
    "jpeg_header_ok": False,
    "jpeg_sof_present": False,
    "jpeg_sos_present": False,
    "jpeg_exif_present": False,
    "jpeg_segments_count": 0,
    "parser_ok": False,
    "structure_consistent": False,
}

# Главная функция парсера JPEG
def parse_jpeg(path: str) -> dict:
    try:
        # Попытка чтения файла
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception:
            return DEF_RETURN.copy()

        # Проверка SOI
        jpeg_header_ok = len(data) >= 2 and data[0] == 0xFF and data[1] == SOI
        if not jpeg_header_ok:
            return DEF_RETURN.copy()

        # Переменные состояния парсера
        pos = 2  # Позиция сразу после чтения SOI
        n = len(data)
        steps = 0

        segments_count = 0
        sof_present = False
        sos_present = False
        exif_present = False

        # Вспомогательная функция: поиск следующего префикса маркера (байт 0xFF)
        def find_next_marker(start: int) -> int:
            if start >= n:
                return -1
            if data[start] == 0xFF:
                return start
            idx = data.find(b"\xFF", start)
            return idx

        # Итеративный обход сегментов файла
        while pos < n and steps < MAX_SEGMENTS:
            steps += 1

            # Проверка на то, что текущая позиция чтения это маркер префикса (байт 0xFF)
            # Если позиция чтения находится внутри сжатых данных, т.е. после маркера SOS, обход заканчивается
            if data[pos] != 0xFF:
                if sos_present:
                    break
                next_ff = find_next_marker(pos)
                if next_ff == -1:
                    break
                pos = next_ff

            # Пропуск всех "заполняющих" байтов (0xFF)
            while pos < n and data[pos] == 0xFF:
                pos += 1
            if pos >= n:
                break

            marker = data[pos]
            pos += 1  # Переход к данным или длине сегмента

            # Обработка маркеров без длины: RSTn и TEM
            if (RST0 <= marker <= RST7) or marker == TEM:
                segments_count += 1
                continue

            # Обработчик исключения - случай, когда SOI внутри потока
            if marker == SOI:
                segments_count += 1
                continue

            # EOI (конец изображения) завершает обход 
            if marker == EOI:
                segments_count += 1
                break

            # Остальные маркеры имеют 2-байтную длину 
            if pos + 2 > n:
                break
            seg_len = struct.unpack_from(">H", data, pos)[0]
            seg_data_start = pos + 2
            seg_data_end = seg_data_start + (seg_len - 2)
            if seg_len < 2 or seg_data_end > n:
                break  # Сегмент некорректной длины - завершение обхода

            # Обновление признаков на основе текущего сегмента
            if marker in SOF_MARKERS:
                sof_present = True
            if marker == SOS:
                sos_present = True
            if marker == 0xE1:
                # APP1: проверка на сигнатуру EXIF 'Exif\x00\x00' в начале данных сегмента
                if seg_data_start + 6 <= n and data[seg_data_start:seg_data_start + 6] == b"Exif\x00\x00":
                    exif_present = True

            segments_count += 1

            # После маркера SOS идут сами данные - обход завершается
            if marker == SOS:
                break

            # Переход к следующему сегменту
            pos = seg_data_end

        # Расчет сводных булевых признаков
        parser_ok = bool(jpeg_header_ok and (sof_present or sos_present) and segments_count >= 3)
        structure_consistent = bool(jpeg_header_ok and sof_present and sos_present and segments_count >= 4)

        # Возврат словаря признаков
        return {
            "jpeg_header_ok": bool(jpeg_header_ok),
            "jpeg_sof_present": bool(sof_present),
            "jpeg_sos_present": bool(sos_present),
            "jpeg_exif_present": bool(exif_present),
            "jpeg_segments_count": int(segments_count),
            "parser_ok": bool(parser_ok),
            "structure_consistent": bool(structure_consistent),
        }
    # Обработка любых исключений
    except Exception:
        return DEF_RETURN.copy()