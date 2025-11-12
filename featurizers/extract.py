# extract.py

from __future__ import annotations

import csv
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import yaml
from featurizers import sniff
from featurizers.features_a import AggregatorA
from featurizers.features_b import AggregatorB
from featurizers.features_c import AggregatorC
from featurizers.parser_registry import get_parser, get_parser_enc


# Определение путей к файлу конфигурации
CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
CONFIG_FILE = CONFIG_DIR / "features.yaml"


# Загрузка файла конфигурации
def load_cfg() -> dict:
    if not CONFIG_FILE.is_file():
        raise FileNotFoundError(f"features.yaml not found at: {CONFIG_FILE}")
    with CONFIG_FILE.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        return data if data is not None else {}


# Итератор для рекурсивного обхода файлов в директории
def iter_files(root_dir: str):
    for dirpath, _, filenames in os.walk(root_dir):
        for name in filenames:
            yield os.path.join(dirpath, name)


# Сбор полной схемы признаков (всех колонок) из features.yaml
def collect_schema(cfg: dict) -> Tuple[List[str], Dict[str, str]]:
    sections = cfg.get("features", {}) or {}
    cols: List[str] = []
    types: Dict[str, str] = {}
    seen = set()
    for _, items in sections.items():
        if not isinstance(items, list):
            continue
        for it in items:
            if not isinstance(it, dict):
                continue
            name = it.get("name")
            typ = it.get("type")
            if not name:
                continue
            if name in seen:
                continue
            seen.add(name)
            cols.append(name)
            if typ:
                types[name] = str(typ)
    return cols, types


# Приведение типов значений признаков в соответствие со схемой
def normalize_value(val: Any, typ: str) -> Any:
    if val is None:
        return None
    t = (typ or "").lower()
    try:
        if t == "bool":
            return val if isinstance(val, bool) else val
        if t == "int":
            return int(val)
        if t == "float":
            return float(val)
        if t == "string":
            return str(val)
    except Exception:
        return val
    return val


# Класс контекста для извлечения признаков, который хранит классы агрегаторов (A, B, C) и загруженную схему из файла конфигурации
class ExtractContext:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.columns, self.column_types = collect_schema(cfg)
        self.allowed = set(self.columns)
        self.agg_a = AggregatorA(cfg)
        self.agg_b = AggregatorB(cfg)
        self.agg_c = AggregatorC(cfg)


# Главная функция извлечения признаков для одного файла
def extract_feats(
    file_path: str,
    cfg: dict,
    *,
    context: Optional[ExtractContext] = None,
) -> Dict[str, Any]:
    # Создание или использование существующего контекста
    ctx = context or ExtractContext(cfg)

    # 1. Вызов sniff.py для общих признаков
    snf = sniff.sniff(file_path, ctx.cfg)

    # 2. Вызов обработчика признаков корректности структуры
    fam = str(snf.get("format_family", "other"))
    parser = get_parser(fam)
    if parser is None:
        # Если обработчик не найден, заполняется None
        parser_feats: Dict[str, Any] = {"parser_ok": None, "structure_consistent": None}
    else:
        try:
            # Запуск обработчика
            parser_feats = dict(parser(file_path)) or {}
        except Exception:
            # Обработчик ошибок
            parser_feats = {"parser_ok": None, "structure_consistent": None}

    # Агрегация признаков корректности структуры
    agg_feats = ctx.agg_a.collect(file_path, sniffer=snf, parser_feats=parser_feats)

    # 3. Вызов обработчика признаков легитимного шифрования
    enc_family = f"{fam}_enc"
    enc_parser_feats: Dict[str, Any] = {}
    # Обработчики легитимного шифрования запускаются, только если обработчик корректности структуры подтвердил корректность файла
    if agg_feats.get("parser_ok") is True:
        enc_parser = get_parser_enc(enc_family)
        if enc_parser is not None:
            try:
                # Запуск обработчика
                enc_parser_feats = dict(enc_parser(file_path)) or {}
            except Exception:
                enc_parser_feats = {}

    # Агрегация признаков легитимного шифрования
    agg_enc_feats = ctx.agg_b.collect(enc_family, enc_feats=enc_parser_feats)
    if agg_enc_feats:
        agg_feats.update(agg_enc_feats)
    for name in getattr(ctx.agg_b, "columns", []):
        agg_feats.setdefault(name, None)

    # 4. Вызов агрегатора статистических признаков
    stat_feats = ctx.agg_c.collect(file_path)
    if stat_feats:
        agg_feats.update(stat_feats)
    # Добавление всех колонок класса C
    for name in getattr(ctx.agg_c, "columns", []):
        agg_feats.setdefault(name, None)

    # 5. Проверка соответствия итогового набора признаков схеме из файла конфигурации
    keys_set = set(agg_feats.keys())
    missing = [c for c in ctx.columns if c not in keys_set]
    extra = [k for k in agg_feats.keys() if k not in ctx.allowed]
    if missing or extra:
        msgs: List[str] = []
        if missing:
            msgs.append(f"пропущенные признаки: {missing}")
        if extra:
            msgs.append(f"неожиданные признаки: {extra}")
        raise RuntimeError(f"Несоответствие схемы для {file_path}: {', '.join(msgs)}")

    # 6. Нормализация типов и возврат результата
    return {
        name: normalize_value(agg_feats.get(name), ctx.column_types.get(name, ""))
        for name in ctx.columns
    }


# Внутренняя функция для обработки целой директории (для CLI)
def _extract_directory(input_dir: str, output_dir: str, cfg: dict) -> Tuple[str, int]:
    ctx = ExtractContext(cfg)
    os.makedirs(output_dir, exist_ok=True)
    out_csv = os.path.join(output_dir, "features_test.csv")

    rows: List[Dict[str, Any]] = []
    for path in iter_files(input_dir):
        feats = extract_feats(path, cfg, context=ctx)
        row = {"path": os.path.relpath(path, start=input_dir).replace("\\", "/")}
        row.update(feats)
        rows.append(row)

    # Запись результатов в CSV
    fieldnames = ["path"] + ctx.columns
    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow({k: ("" if r.get(k) is None else r.get(k)) for k in fieldnames})

    return out_csv, len(rows)


# Точка входа для запуска через командную строку
def main(argv: Optional[Iterable[str]] = None) -> None:
    args = list(argv or [])
    if not args:
        import sys
        args = sys.argv[1:]

    if len(args) != 2:
        raise SystemExit("Использование: python -m featurizers.extract <INPUT_DIR> <OUTPUT_DIR>")

    input_dir, output_dir = args
    if not os.path.isdir(input_dir):
        raise SystemExit(f"Директория не найдена: {input_dir}")

    cfg = load_cfg()
    out_csv, count = _extract_directory(input_dir, output_dir, cfg)
    print(f"Записано {count} строк в {out_csv}")


if __name__ == "__main__":
    main()