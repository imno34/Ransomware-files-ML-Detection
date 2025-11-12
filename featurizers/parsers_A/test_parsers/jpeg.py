# parsers/jpeg_dir_parser.py
# Извлекаемые признаки:
#  - jpeg_header_ok (bool)          — начинается ли файл с SOI (0xFF 0xD8)
#  - jpeg_sof_present (bool)        — присутствует ли любой SOF (baseline/progressive и пр.)
#  - jpeg_sos_present (bool)        — присутствует ли SOS (Start Of Scan)
#  - jpeg_exif_present (bool)       — есть ли APP1 с сигнатурой 'Exif\0\0'
#  - jpeg_segments_count (int)      — число сегментов (без SOI), подсчитанных до (и включая) SOS/EOI
#
# Запуск:
#   python parsers/jpeg_dir_parser.py <DIR_WITH_FILES>
#
# Примечания:
#   - Предполагается, что в директории лежат JPEG-файлы; расширение не проверяем.
#   - Минимум обработчиков ошибок — проблемные файлы пропускаются молча.

import os
import sys
import struct

# JPEG маркеры
SOI = 0xD8  # Start of Image
EOI = 0xD9  # End of Image
SOS = 0xDA  # Start of Scan
TEM = 0x01  # Temporary (без длины)
# Restart markers (без длины)
RST0, RST7 = 0xD0, 0xD7

# Набор SOF-маркеров (все режимы, кроме дифференциальных без потерь, если не нужны — но включим все SOF0..SOF15 кроме DHT/DAC)
SOF_MARKERS = {
    0xC0, 0xC1, 0xC2, 0xC3,
    0xC5, 0xC6, 0xC7,
    0xC9, 0xCA, 0xCB,
    0xCD, 0xCE, 0xCF
}

MAX_SEGMENTS = 200000  # предохранитель, чтобы не зациклиться на битом файле

def parse_jpeg_features_one(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception:
        return None

    # Проверка заголовка SOI
    jpeg_header_ok = len(data) >= 2 and data[0] == 0xFF and data[1] == SOI
    if not jpeg_header_ok:
        return {
            "jpeg_header_ok": False,
            "jpeg_sof_present": False,
            "jpeg_sos_present": False,
            "jpeg_exif_present": False,
            "jpeg_segments_count": 0,
        }

    pos = 2  # после SOI
    segments_count = 0
    sof_present = False
    sos_present = False
    exif_present = False

    steps = 0
    n = len(data)

    while pos < n and steps < MAX_SEGMENTS:
        steps += 1

        # маркеры начинаются с 0xFF, может быть "набивка" из нескольких 0xFF
        if data[pos] != 0xFF:
            # внутри сжатых данных после SOS могут быть байт-стаффинги; обычно мы выходим по SOS
            # если SOS уже встретился — можно завершать разбор
            if sos_present:
                break
            # иначе пытаемся найти следующий 0xFF
            next_ff = data.find(b'\xFF', pos)
            if next_ff == -1:
                break
            pos = next_ff

        # пропускаем все 0xFF (fill bytes)
        while pos < n and data[pos] == 0xFF:
            pos += 1
        if pos >= n:
            break

        marker = data[pos]
        pos += 1  # указываем на начало возможной длины сегмента

        # Маркеры без длины: RSTn и TEM
        if (RST0 <= marker <= RST7) or marker == TEM:
            segments_count += 1
            # продолжаем искать следующий сегмент
            continue

        # SOI (внутри) — редкий случай; просто считаем сегмент и идём дальше
        if marker == SOI:
            segments_count += 1
            continue

        # EOI — конец изображения
        if marker == EOI:
            segments_count += 1
            break

        # Для остальных должен быть 2-байтовый размер (BE), включающий эти 2 байта
        if pos + 2 > n:
            break
        seg_len = struct.unpack(">H", data[pos:pos+2])[0]
        seg_data_start = pos + 2
        seg_data_end = seg_data_start + (seg_len - 2)
        if seg_len < 2 or seg_data_end > n:
            break  # повреждение

        # Обновляем признаки
        if marker in SOF_MARKERS:
            sof_present = True
        if marker == SOS:
            sos_present = True
        # EXIF ищем в APP1 (0xE1): первые 6 байт данных 'Exif\0\0'
        if marker == 0xE1:
            # проверяем только начало сегмента
            if seg_data_start + 6 <= n and data[seg_data_start:seg_data_start+6] == b'Exif\x00\x00':
                exif_present = True

        segments_count += 1

        # После SOS идёт «скан» сжатых данных до EOI; мы фиксируем sos_present и выходим,
        # чтобы не застрять на энтропийных данных
        if marker == SOS:
            # Можно быстро проверить EOI, но для наших признаков это не требуется
            break

        # Переходим к следующему сегменту
        pos = seg_data_end

    return {
        "jpeg_header_ok": bool(jpeg_header_ok),
        "jpeg_sof_present": bool(sof_present),
        "jpeg_sos_present": bool(sos_present),
        "jpeg_exif_present": bool(exif_present),
        "jpeg_segments_count": int(segments_count),
    }

def main(dir_path):
    cols = [
        "file",
        "jpeg_header_ok",
        "jpeg_sof_present",
        "jpeg_sos_present",
        "jpeg_exif_present",
        "jpeg_segments_count",
    ]
    print("\t".join(cols))

    for fname in sorted(os.listdir(dir_path)):
        path = os.path.join(dir_path, fname)
        if not os.path.isfile(path):
            continue
        try:
            feats = parse_jpeg_features_one(path)
            if feats is None:
                continue
            row = {"file": fname, **feats}
            print("\t".join(str(row[c]) for c in cols))
        except Exception:
            # минимализм: проблемный файл пропускаем
            pass

if __name__ == "__main__":
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    main(d)
