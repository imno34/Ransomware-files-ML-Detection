# parsers_A/ooxml_feat.py

import argparse
import csv
import posixpath
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

# Ключевые пути/файлы OOXML
CONTENT_TYPES = "[Content_Types].xml"
CORE_DOCX = "word/document.xml"
CORE_XLSX = "xl/workbook.xml"
CORE_PPTX = "ppt/presentation.xml"
RELS_ROOT = "_rels/.rels"

OFFICEDOC_REL_TYPES = {
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument",
    "http://purl.oclc.org/ooxml/officeDocument/relationships/officeDocument",
}

# Параметры производительности
RELS_EARLY_STOP = 20       # остановка подсчета для оптимизации работы на больших файлах
CT_SCAN_BYTES = 4096       # сколько байт читать из [Content_Types].xml для быстрой проверки

# Стандартные значения возврата парсера
DEF_RETURN = {
    "ooxml_detected": False,
    "ooxml_coreparts_present": False,
    "ooxml_rel_count": 0,
    "ooxml_pkg_ok": False,
    "ooxml_content_types_valid": False,
    "ooxml_relationships_graph_valid": False,
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

def xml_local_name(tag: str) -> str:
    # Возвращает локальное имя XML-тега без namespace:
    # "{namespace}Types" -> "Types"
    if not tag:
        return ""
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def normalize_zip_path(path_value: str) -> str:
    # Нормализует внутренний путь ZIP-контейнера:
    # - POSIX-разделители
    # - без ведущего "/"
    normalized = posixpath.normpath((path_value or "").replace("\\", "/")).lstrip("/")
    return "" if normalized in ("", ".") else normalized


def validate_content_types_xml(zf) -> bool:
    # Проверка [Content_Types].xml:
    # 1) читается как XML
    # 2) корневой элемент = Types
    # 3) есть хотя бы один Default и/или Override
    # 4) есть Override хотя бы для одного core part:
    #    word/document.xml или xl/workbook.xml или ppt/presentation.xml
    try:
        with zf.open(CONTENT_TYPES, "r") as fh:
            xml_bytes = fh.read()
        root = ET.fromstring(xml_bytes)
    except Exception:
        return False

    if xml_local_name(root.tag) != "Types":
        return False

    has_default = False
    has_override = False
    has_core_override = False
    core_overrides = {
        f"/{CORE_DOCX}".lower(),
        f"/{CORE_XLSX}".lower(),
        f"/{CORE_PPTX}".lower(),
    }

    for child in root:
        local = xml_local_name(child.tag)
        if local == "Default":
            has_default = True
        elif local == "Override":
            has_override = True
            part_name = (child.attrib.get("PartName") or "").strip().lower()
            if part_name in core_overrides:
                has_core_override = True

    if not (has_default or has_override):
        return False
    return has_core_override


def validate_relationships_graph(zf, names_set) -> bool:
    # Проверка графа отношений:
    # 1) есть _rels/.rels
    # 2) XML валиден, корневой элемент = Relationships
    # 3) есть хотя бы один Relationship типа officeDocument
    # 4) target этого Relationship существует в контейнере
    if RELS_ROOT not in names_set:
        return False

    try:
        with zf.open(RELS_ROOT, "r") as fh:
            xml_bytes = fh.read()
        root = ET.fromstring(xml_bytes)
    except Exception:
        return False

    if xml_local_name(root.tag) != "Relationships":
        return False

    normalized_names = {normalize_zip_path(n).lower() for n in names_set}
    relationships = [elem for elem in root if xml_local_name(elem.tag) == "Relationship"]
    if not relationships:
        return False

    has_office_document_rel = False
    has_existing_target = False
    for rel in relationships:
        rel_type = (rel.attrib.get("Type") or "").strip()
        rel_target = (rel.attrib.get("Target") or "").strip()
        target_mode = (rel.attrib.get("TargetMode") or "").strip().lower()

        is_officedoc_rel = (
            rel_type in OFFICEDOC_REL_TYPES
            or rel_type.endswith("/officeDocument")
        )
        if not is_officedoc_rel:
            continue

        has_office_document_rel = True
        if target_mode == "external" or not rel_target:
            continue

        target_path = normalize_zip_path(rel_target).lower()
        if target_path in normalized_names:
            has_existing_target = True
            break

    return bool(has_office_document_rel and has_existing_target)


def parse_ooxml(path: str) -> dict:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()

            struct_detected, core_present, has_content_types, names_set = fast_detect_ooxml(names)
            rel_count = fast_rel_count(names)

            # проверка наличия каталогов OOXML
            has_ooxml_dirs = any(n.startswith("word/") or n.startswith("xl/") or n.startswith("ppt/") for n in names_set)

            pkg_ok = fast_pkg_ok(zf, has_content_types, core_present, has_ooxml_dirs)
            content_types_valid = validate_content_types_xml(zf)
            relationships_graph_valid = validate_relationships_graph(zf, names_set)

            # Расчет сводных булевых признаков
            parser_ok = struct_detected and content_types_valid and (core_present or relationships_graph_valid)
            structure_consistent = parser_ok and core_present and relationships_graph_valid
            return {
                "ooxml_detected": bool(struct_detected),
                "ooxml_coreparts_present": bool(core_present),
                "ooxml_rel_count": int(rel_count),
                "ooxml_pkg_ok": bool(pkg_ok),
                "ooxml_content_types_valid": bool(content_types_valid),
                "ooxml_relationships_graph_valid": bool(relationships_graph_valid),
                "parser_ok": bool(parser_ok),
                "structure_consistent": bool(structure_consistent)
            }
    except Exception:
        return DEF_RETURN.copy()
    
def main() -> None:
    parser = argparse.ArgumentParser(description="Минималистичный CLI для OOXML-парсера признаков.")
    parser.add_argument("input_path", type=Path, help="Путь к файлу или директории с файлами.")
    parser.add_argument("output_dir", type=Path, help="Директория для сохранения CSV с признаками.")
    args = parser.parse_args()

    input_path = args.input_path.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if input_path.is_file():
        files = [input_path]
        base_dir = input_path.parent
    elif input_path.is_dir():
        files = sorted([p for p in input_path.rglob("*") if p.is_file()])
        base_dir = input_path
    else:
        raise SystemExit(f"Путь не найден: {input_path}")

    if not files:
        raise SystemExit(f"Файлы не найдены: {input_path}")

    rows = []
    for file_path in files:
        result = parse_ooxml(str(file_path))
        try:
            rel_path = file_path.relative_to(base_dir)
        except ValueError:
            rel_path = file_path.name
        row = {"path": str(rel_path).replace("\\", "/")}
        row.update(result)
        rows.append(row)

    csv_path = output_dir / "ooxml_parser_features.csv"
    fieldnames = list(rows[0].keys())

    with csv_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: ("" if row.get(k) is None else row.get(k)) for k in fieldnames})

    print(f"Обработано файлов: {len(rows)}")
    print(f"Признаки сохранены в {csv_path}")


if __name__ == "__main__":
    main()
