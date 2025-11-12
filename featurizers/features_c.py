# features_c.py

from __future__ import annotations

import math
import os
from collections import deque
from typing import Any, Dict, List, Tuple


# Размер блока для чтения файла
CHUNK_SIZE = 64 * 1024
# Размер сегмента для анализа заголовка и трейлера файла
SEGMENT_SIZE = 32 * 1024


# Сбор схемы для статистических признаков из файла конфигурации
def collect_schema(cfg: dict) -> Tuple[List[str], Dict[str, str]]:
    section = (cfg.get("features", {}) or {}).get("statistic", [])
    cols: List[str] = []
    types: Dict[str, str] = {}
    for item in section:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        typ = item.get("type")
        if not name:
            continue
        cols.append(str(name))
        if typ:
            types[str(name)] = str(typ)
    return cols, types


# Функция для вычисления энтропии Шеннона по массиву байт
def entropy_from_bytes(data: bytes) -> float | None:
    n = len(data)
    if n == 0:
        return None
    # Подсчет частоты каждого байта
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    return entropy_from_counts(counts, n)


# Функция для вычисления энтропии по готовому списку частот
def entropy_from_counts(counts: List[int], total: int) -> float | None:
    if total == 0:
        return None
    entropy = 0.0
    for cnt in counts:
        if cnt == 0:
            continue
        p = cnt / total
        entropy -= p * math.log2(p)
    return entropy


# Функция для вычисления минимальной энтропии
def min_entropy(counts: List[int], total: int) -> float | None:
    if total == 0:
        return None
    m = max(counts)
    if m == 0:
        return None
    # Вероятность самого частого символа
    p_max = m / total
    return -math.log2(p_max)


# Функция для вычисления критерий Пирсона
def chi_square(counts: List[int], total: int) -> float | None:
    if total == 0:
        return None
    # Ожидаемая частота для каждого байта при равномерном распределении
    expected = total / 256.0
    if expected == 0:
        return None
    chi2 = 0.0
    for cnt in counts:
        diff = cnt - expected
        chi2 += (diff * diff) / expected
    return chi2


# Функция для вычисления индекса совпадений
def index_of_coincidence(counts: List[int], total: int) -> float | None:
    if total <= 1:
        return None
    numerator = sum(cnt * (cnt - 1) for cnt in counts)
    denominator = total * (total - 1)
    if denominator == 0:
        return None
    return numerator / denominator


# Главная функция сбора байтовой статистики за один проход по файлу
def byte_statistics(path: str) -> Tuple[List[int], int, bytes, bytes]:
    counts = [0] * 256
    total = 0
    head = bytearray()
    tail = deque(maxlen= SEGMENT_SIZE)

    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            total += len(chunk)
            # Обновление общего списка частот
            for b in chunk:
                counts[b] += 1

            # Заполнение заголовка
            if len(head) < SEGMENT_SIZE:
                need = SEGMENT_SIZE - len(head)
                head.extend(chunk[:need])

            # Обновление трейлера
            tail.extend(chunk)

    return counts, total, bytes(head), bytes(tail)


class AggregatorC:
    # Инициализация агрегатора
    def __init__(self, cfg: dict | None = None) -> None:
        self.cfg = cfg or {}
        # Загрузка схемы признаков при создании объекта
        self.columns, self.column_types = collect_schema(self.cfg)

    # Метод сбора всех статистических признаков для одного файла
    def collect(self, path: str) -> Dict[str, Any]:
        if not self.columns:
            return {}

        # Словарь для результатов
        stats: Dict[str, Any] = {name: None for name in self.columns}

        try:
            # 1. Сбор базовой статистики (гистограмма, заголовок, трейлер)
            counts, total, head_bytes, tail_bytes = byte_statistics(path)
        except Exception:
            # Обработчик ошибок
            return stats

        # 2. Расчет статистических метрик
        
        # Глобальная энтропия (по всему файлу)
        if "entropy_global" in stats:
            stats["entropy_global"] = entropy_from_counts(counts, total)
        # Глобальная min-энтропия
        if "min_entropy_global" in stats:
            stats["min_entropy_global"] = min_entropy(counts, total)
        # Энтропия заголовка
        if "entropy_head" in stats:
            stats["entropy_head"] = entropy_from_bytes(head_bytes)
        # Энтропия трейлера
        if "entropy_tail" in stats:
            stats["entropy_tail"] = entropy_from_bytes(tail_bytes)
        # Критерий Пирсона
        if "byte_chi2" in stats:
            stats["byte_chi2"] = chi_square(counts, total)
        # Индекс совпадений
        if "ic_index" in stats:
            stats["ic_index"] = index_of_coincidence(counts, total)

        return stats


__all__ = ["AggregatorC"]
