# features_a.py

from __future__ import annotations

from typing import Any, Dict, List, Tuple


# Ключи общих признаков, получаемых от sniff.py
_COMMON_KEYS = ("size_bytes", "log_size", "magic_ok", "format_family", "magic_family")


# Сбор схемы признаков из конфигурационного файла (cfg['features'])
# Возврщщает (ordered_columns, type_by_name)
# Дубликаты имен удаляются, сохраняется первое вхождение, т.к. parser_ok и structure_consistent считаются для всех
def _collect_schema(cfg: dict) -> Tuple[List[str], Dict[str, str]]:
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

class AggregatorA:
    def __init__(self, cfg: dict | None = None) -> None:
        self.cfg = cfg or {}

    # Сбор признаков для одного файла
    # Возвращает плоский словарь (dict) с:
    #   - общими признаками от sniff.py
    #   - признаками корректности структуры от обработчика
    def collect(
        self,
        path: str,
        *,
        sniffer: Dict[str, Any] | None = None,
        parser_feats: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:

        # 1) Получение общих признаков от сниффера (предоставляются экстрактором)
        snf = sniffer or {}
        common: Dict[str, Any] = {k: snf.get(k) for k in _COMMON_KEYS}

        # 2) Получение признаков парсера (предоставляются экстрактором; по умолчанию пустые)
        if parser_feats is None:
            parser_feats = {}

        # Гарантия явного наличия ключей (parser_ok, structure_consistent),
        parser_feats.setdefault("parser_ok", None)
        parser_feats.setdefault("structure_consistent", None)

        # 3) Слияние общих признаков и признаков парсера
        merged: Dict[str, Any] = {**common, **parser_feats}

        # 3.2) Добавление всех оставшихся признаков из файла конфигурации со значением NULL (None)
        cols, _types = _collect_schema(self.cfg)
        out: Dict[str, Any] = {name: None for name in cols}
        for k, v in merged.items():
            if k in out:
                out[k] = v
        return out


# Публичный метод агрегатора А
def aggregate(
    path: str,
    cfg: dict | None = None,
    *,
    sniffer: Dict[str, Any] | None = None,
    parser_feats: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    return AggregatorA(cfg).collect(path, sniffer=sniffer, parser_feats=parser_feats)


__all__ = ["AggregatorA", "aggregate"]