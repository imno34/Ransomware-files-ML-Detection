# parsers/ooxml_dir_parser_fast.py
# Быстрый парсер OOXML-признаков по директории:
#  - ooxml_detected (bool)            — наличие структуры OOXML
#  - ooxml_coreparts_present (bool)   — word/document.xml | xl/workbook.xml | ppt/presentation.xml
#  - ooxml_rel_count (int)            — количество *.rels (с ранним стопом)
#  - ooxml_pkg_ok (bool)              — легкая согласованность пакета без XML-парсинга
#
# Запуск:
#   python parsers/ooxml_dir_parser_fast.py <DIR_WITH_FILES>
#
# Примечания:
#   - Предполагается, что в директории лежат ZIP/OOXML файлы (магия не проверяется).
#   - Минимум обработчиков ошибок — проблемные файлы пропускаются молча.

import os
import sys
import zipfile

# Ключевые пути/файлы OOXML
CONTENT_TYPES = "[Content_Types].xml"
CORE_DOCX = "word/document.xml"
CORE_XLSX = "xl/workbook.xml"
CORE_PPTX = "ppt/presentation.xml"

# Параметры производительности
RELS_EARLY_STOP = 20       # если .rels > 20, дальше не считаем (хватает «много»)
CT_SCAN_BYTES = 4096       # сколько байт читать из [Content_Types].xml для быстрой проверки

def fast_detect_ooxml(names):
    """Быстрые детекторы OOXML по списку имён (namelist)."""
    names_set = set(names)

    has_content_types = CONTENT_TYPES in names_set
    core_present = (CORE_DOCX in names_set) or (CORE_XLSX in names_set) or (CORE_PPTX in names_set)

    # слабый сигнал наличия структуры OOXML (каталоги word/|xl/|ppt/)
    has_ooxml_dirs = False
    for n in names_set:
        # проверяем только первые 4 символа, чтобы не делать startswith 3 раза
        if len(n) >= 4:
            p = n[:4]
            if p == "word" or p == "xl/_"[:2] or p == "ppt/":
                # упрощённая проверка: любой объект внутри word/|xl/|ppt/
                if n.startswith("word/") or n.startswith("xl/") or n.startswith("ppt/"):
                    has_ooxml_dirs = True
                    break

    detected = bool(has_content_types and (core_present or has_ooxml_dirs))
    return detected, core_present, has_content_types, names_set

def fast_rel_count(names):
    """Подсчёт *.rels с ранней остановкой."""
    cnt = 0
    for n in names:
        # избегаем .lower(); проверяем сразу оба варианта
        if n.endswith(".rels") or n.endswith(".RELS"):
            cnt += 1
            if cnt > RELS_EARLY_STOP:
                return RELS_EARLY_STOP + 1
    return cnt

def fast_pkg_ok(zf, has_content_types, core_present, has_ooxml_dirs):
    """
    Лёгкая версия «согласованности пакета»:
      - должен существовать [Content_Types].xml
      - и либо есть core-файл, либо есть каталоги OOXML
      - опционально: проверяем первые байты [Content_Types].xml на <Types>/<Override>
    """
    if not has_content_types:
        return False
    if not (core_present or has_ooxml_dirs):
        return False

    try:
        with zf.open(CONTENT_TYPES, "r") as fh:
            head = fh.read(CT_SCAN_BYTES)
            # быстрые «сигнатуры» XML без парсинга
            has_types = (b"<Types" in head) or (b":Types" in head)  # с/без namespace
            has_override = (b"<Override" in head) or (b":Override" in head)
            # даже если <Override> не увидели в первых КБ, допускаем OK при наличии core/dirs
            return bool(has_types)
    except Exception:
        # нет доступа/битый файл — считаем пакет невалидным
        return False

def parse_ooxml_features_one(path):
    with zipfile.ZipFile(path, "r") as zf:
        names = zf.namelist()

        detected, core_present, has_content_types, names_set = fast_detect_ooxml(names)
        rel_count = fast_rel_count(names)

        # проверка наличия каталогов OOXML (повторяем в явном виде, чтобы не плодить состояния)
        has_ooxml_dirs = any(n.startswith("word/") or n.startswith("xl/") or n.startswith("ppt/") for n in names_set)

        pkg_ok = fast_pkg_ok(zf, has_content_types, core_present, has_ooxml_dirs)
        parser_ok = detected and pkg_ok and (core_present or rel_count > 0)
        structure_consistent = parser_ok and core_present and (rel_count >= 2)
        return {
            "ooxml_detected": bool(detected),
            "ooxml_coreparts_present": bool(core_present),
            "ooxml_rel_count": int(rel_count),
            "ooxml_pkg_ok": bool(pkg_ok),
            "parser_ok": bool(parser_ok),
            "structure_consistent": bool(structure_consistent)
        }

def main(dir_path):
    cols = ["file", "ooxml_detected", "ooxml_coreparts_present", "ooxml_rel_count", "ooxml_pkg_ok", "parser_ok", "structure_consistent"]
    print("\t".join(cols))

    for fname in sorted(os.listdir(dir_path)):
        path = os.path.join(dir_path, fname)
        if not os.path.isfile(path):
            continue
        try:
            feats = parse_ooxml_features_one(path)
            row = {"file": fname, **feats}
            print("\t".join(str(row[c]) for c in cols))
        except Exception:
            # минимализм: ошибки парсинга молча игнорируются
            pass

if __name__ == "__main__":
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    main(d)
