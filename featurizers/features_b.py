# features_b.py

from __future__ import annotations

from typing import Any, Dict, List, Tuple


# Внутренняя функция для сбора схемы признаков легитимного шифрования из файла конфигурации
# Собирает только секции, оканчивающиеся на "_enc"
def _collect_schema(cfg: dict) -> Tuple[Dict[str, List[str]], List[str], Dict[str, str]]:

    sections = cfg.get("features", {}) or {}
    family_columns: Dict[str, List[str]] = {}
    all_columns: List[str] = []
    types: Dict[str, str] = {}
    seen_global = set()

    # Итеративный обход всех секций в файле конфигурации
    for section_name, items in sections.items():
        if not isinstance(items, list):
            continue
        if not str(section_name).endswith("_enc"):
            continue

        cols: List[str] = []
        for it in items:
            if not isinstance(it, dict):
                continue
            name = it.get("name")
            typ = it.get("type")
            if not name:
                continue
            cols.append(name)
            if name not in seen_global:
                seen_global.add(name)
                all_columns.append(name)
                if typ:
                    types[name] = str(typ)
        family_columns[str(section_name)] = cols

    return family_columns, all_columns, types


class AggregatorB:
    def __init__(self, cfg: dict | None = None) -> None:
        self.cfg = cfg or {}
        # Загрузка схемы признаков класса B при инициализации
        self.family_columns, self.columns, self.column_types = _collect_schema(self.cfg)

    # Сбор признаков класса B для одного файла
    def collect(self, family: str, *, enc_feats: Dict[str, Any] | None = None) -> Dict[str, Any]:

        # Получение списка ожидаемых колонок для этого семейства
        cols = self.family_columns.get(str(family), [])
        if not cols:
            return {}

        # Создание словаря с None значениями по умолчанию
        out: Dict[str, Any] = {name: None for name in cols}
        
        # Заполнение фактическими значениями от обработчика, если они есть
        if enc_feats:
            for key, value in enc_feats.items():
                if key in out:
                    out[key] = value
        return out


__all__ = ["AggregatorB"]
