# parsers_A/ooxml_feat.py

import zipfile

# Ключевые пути/файлы OOXML
CONTENT_TYPES = "[Content_Types].xml"
CORE_DOCX = "word/document.xml"
CORE_XLSX = "xl/workbook.xml"
CORE_PPTX = "ppt/presentation.xml"

# Параметры производительности
RELS_EARLY_STOP = 20       # остановка подсчета для оптимизации работы на больших файлах
CT_SCAN_BYTES = 4096       # сколько байт читать из [Content_Types].xml для быстрой проверки

# Стандартные значения возврата парсера
DEF_RETURN = {
    "ooxml_detected": False,
    "ooxml_coreparts_present": False,
    "ooxml_rel_count": 0,
    "ooxml_pkg_ok": False,
    "parser_ok": False,
    "structure_consistent": False,
}

def fast_detect_ooxml(names):
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

    struct_detected = bool(has_content_types and (core_present or has_ooxml_dirs))
    return struct_detected, core_present, has_content_types, names_set

def fast_rel_count(names):
    cnt = 0
    for n in names:
        # избегаем .lower(); проверяем сразу оба варианта
        if n.endswith(".rels") or n.endswith(".RELS"):
            cnt += 1
            if cnt > RELS_EARLY_STOP:
                return RELS_EARLY_STOP + 1
    return cnt

def fast_pkg_ok(zf, has_content_types, core_present, has_ooxml_dirs):
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
            # даже если <Override> не увидели в первых КБ, допускается при наличии core/dirs
            return bool(has_types)
    except Exception:
        # нет доступа/битый файл
        return False

def parse_ooxml(path: str) -> dict:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()

            struct_detected, core_present, has_content_types, names_set = fast_detect_ooxml(names)
            rel_count = fast_rel_count(names)

            # проверка наличия каталогов OOXML
            has_ooxml_dirs = any(n.startswith("word/") or n.startswith("xl/") or n.startswith("ppt/") for n in names_set)

            pkg_ok = fast_pkg_ok(zf, has_content_types, core_present, has_ooxml_dirs)

            # Расчет сводных булевых признаков
            parser_ok = struct_detected and pkg_ok and (core_present or rel_count > 0)
            structure_consistent = parser_ok and core_present and (rel_count >= 2)
            return {
                "ooxml_detected": bool(struct_detected),
                "ooxml_coreparts_present": bool(core_present),
                "ooxml_rel_count": int(rel_count),
                "ooxml_pkg_ok": bool(pkg_ok),
                "parser_ok": bool(parser_ok),
                "structure_consistent": bool(structure_consistent)
            }
    except Exception:
        return DEF_RETURN.copy()