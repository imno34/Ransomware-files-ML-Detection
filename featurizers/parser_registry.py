#parser_registry.py

from __future__ import annotations

import inspect
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Callable, Dict, List, Optional


def iter_parser_files(subdir: str) -> List[Path]:
    base = Path(__file__).resolve().parent / subdir
    files: List[Path] = []
    if not base.is_dir():
        return files
    for entry in base.iterdir():
        if entry.is_dir():
            # Исключение для пропуска тестовых парсеров
            continue
        if entry.suffix != ".py":
            continue
        if entry.name.startswith("__"):
            continue
        files.append(entry)
    return files


def load_module_from_path(subdir: str, path: Path):
    mod_name = f"featurizers.{subdir}.{path.stem}"
    spec = spec_from_file_location(mod_name, str(path))
    if spec is None or spec.loader is None:
        return None
    module = module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


def fallback_family_from_module(path: Path) -> str:
    stem = path.stem
    if stem.endswith("_feat"):
        return stem[: -len("_feat")]
    return stem


def discover_parsers(subdir: str) -> Dict[str, Callable]:
    registry: Dict[str, Callable] = {}
    for file_path in iter_parser_files(subdir):
        module = load_module_from_path(subdir, file_path)
        if module is None:
            continue

        functions = [
            (name, fn)
            for name, fn in inspect.getmembers(module, inspect.isfunction)
            if name.startswith("parse_")
        ]
        if functions:
            for name, fn in functions:
                family = name[len("parse_") :].strip()
                if family:
                    registry.setdefault(family, fn)
            continue

        fallback = fallback_family_from_module(file_path)
        fn = getattr(module, "parse", None)
        if callable(fn):
            registry.setdefault(fallback, fn)
    return registry


PARSERS_A: Dict[str, Callable] = discover_parsers("parsers_A")
PARSERS_B: Dict[str, Callable] = discover_parsers("parsers_B")


def get_parser(family: str) -> Optional[Callable]:
    # ф-ция вызова обработчиков для признаков корректности структуры

    return PARSERS_A.get(str(family))


def get_parser_enc(family: str) -> Optional[Callable]:
    # ф-ция вызова обработчиков для признаков легитимного шифрования
    return PARSERS_B.get(str(family))


def available_families() -> List[str]:
    return sorted(PARSERS_A.keys())


def available_families_enc() -> List[str]:
    return sorted(PARSERS_B.keys())


__all__ = [
    "PARSERS_A",
    "PARSERS_B",
    "get_parser",
    "get_parser_enc",
    "available_families",
    "available_families_enc",
]

