# dataset.py

from __future__ import annotations

import argparse
import csv
import random
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Tuple, Any
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from featurizers.extract import ExtractContext, collect_schema, extract_feats, load_cfg


# Определение корневых папок для каждого класса
ROOT_FOLDERS = {
    "benign": "benign",
    "benign-encrypted": "benign-encrypted",
    "ransomware-encrypted": "ransomware-encrypted",
}

# Определение пропорций для разделения датасета
SPLIT_RATIOS = {
    "train": 0.70,
    "valid": 0.15,
    "test": 0.15,
}

# Зерно для генератора случайных чисел для воспроизводимости
RANDOM_SEED = 20240101


def parse_filename_metadata(name: str) -> Tuple[int, str, str]:
    #Вычисление sequence_id, orig_ext, curr_ext из имени файла

    if "-" not in name or "." not in name:
        raise ValueError(f"Filename does not fit expected pattern: {name}")

    seq_part, rest = name.split("-", 1)
    try:
        sequence_id = int(seq_part)
    except ValueError as exc:
        raise ValueError(f"Sequence id is not integer in {name}") from exc

    first_dot = rest.find(".")
    last_dot = rest.rfind(".")
    if first_dot == -1 or last_dot == -1:
        raise ValueError(f"Filename does not contain extensions: {name}")

    orig_ext = rest[:first_dot]
    curr_ext = rest[last_dot + 1 :]
    if not orig_ext or not curr_ext:
        raise ValueError(f"Filename parts missing in {name}")

    return sequence_id, orig_ext, curr_ext

# Итератор по файлам датасета в ожидаемых папках (вычисляет признаки для отладки gt_class, absolute_path)
def iter_dataset_files(input_dir: Path) -> Iterable[Tuple[str, Path]]:
    for class_name, folder in ROOT_FOLDERS.items():
        class_dir = input_dir / folder
        if not class_dir.is_dir():
            continue
        for path in class_dir.rglob("*"):
            if path.is_file():
                yield class_name, path

# Стратифицированное разделение групп (sequence_id) по классам на train/valid/test с проверкой распределения
def stratified_group_split(rows: List[Dict[str, Any]]) -> Dict[str, List[int]]:
    # Группировка индексов строк по классу и sequence_id
    class_to_groups: Dict[str, Dict[int, List[int]]] = defaultdict(lambda: defaultdict(list))
    for idx, row in enumerate(rows):
        class_to_groups[row["gt_class"]][row["sequence_id"]].append(idx)

    # Подсчет общего количества строк для каждого класса
    total_class_counts = defaultdict(int)
    for row in rows:
        total_class_counts[row["gt_class"]] += 1

    # Инициализация структур для хранения разделения
    split_assignments = {
        split: {
            "indices": set(),
            "class_counts": defaultdict(int),
            "total": 0,
        }
        for split in SPLIT_RATIOS
    }

    rng = random.Random(RANDOM_SEED)
    split_names = list(SPLIT_RATIOS.keys())

    # Выполнение стратификации для каждого класса
    for cls, seq_to_indices in class_to_groups.items():
        groups = list(seq_to_indices.items())
        rng.shuffle(groups)
        total_groups = len(groups)

        # Расчет распределения для каждой выборки (train/valid/test)
        quotas = {split: 0 for split in split_names}
        # Гарантия как минимум одной группы на сплит, если групп достаточно
        if total_groups >= len(split_names):
            for split in split_names:
                quotas[split] = 1
            remaining = total_groups - len(split_names)
        else:
            remaining = total_groups

        # Распределение оставшихся групп пропорционально
        if remaining > 0:
            float_targets = {split: SPLIT_RATIOS[split] * remaining for split in split_names}
            assigned = 0
            residuals: List[Tuple[float, str]] = []
            for split in split_names:
                base = int(float_targets[split])
                quotas[split] += base
                assigned += base
                residuals.append((float_targets[split] - base, split))

            # Распределение остатков, появившихся из-за округления
            leftover = remaining - assigned
            if leftover > 0:
                residuals.sort(reverse=True)
                for _, split in residuals:
                    if leftover <= 0:
                        break
                    quotas[split] += 1
                    leftover -= 1

        # Корректировка распределения, если сумма не сходится с общим количеством групп
        current_total = sum(quotas.values())
        if current_total != total_groups:
            diff = total_groups - current_total
            ordered = sorted(split_names, key=lambda s: SPLIT_RATIOS[s], reverse=True)
            idx = 0
            while diff != 0:
                split = ordered[idx % len(ordered)]
                if diff > 0:
                    quotas[split] += 1
                    diff -= 1
                else:
                    if quotas[split] > 0:
                        quotas[split] -= 1
                        diff += 1
                idx += 1

        # Распределение групп по выборкам
        pointer = 0
        for split in split_names:
            count = quotas[split]
            if count <= 0:
                continue
            selected = groups[pointer : pointer + count]
            pointer += count
            for seq, indices in selected:
                split_assignments[split]["indices"].update(indices)
                split_assignments[split]["class_counts"][cls] += len(indices)
                split_assignments[split]["total"] += len(indices)

    # Проверка на пересечение групп в разных сплитах
    all_indices = set()
    for split, data in split_assignments.items():
        overlap = all_indices & data["indices"]
        if overlap:
            raise RuntimeError(f"Groups assigned to multiple splits: {overlap}")
        all_indices.update(data["indices"])

    # Проверка, что все строки были распределены
    if len(all_indices) != len(rows):
        missing = set(range(len(rows))) - all_indices
        raise RuntimeError(f"Missing assignments for indices: {missing}")

    # Проверка дрейфа распределения классов
    total_rows = len(rows)
    overall_class_ratio = {
        cls: total_class_counts[cls] / total_rows for cls in total_class_counts
    }
    for split, data in split_assignments.items():
        split_total = max(1, data["total"])
        for cls, overall_ratio in overall_class_ratio.items():
            split_ratio = data["class_counts"][cls] / split_total
            if abs(split_ratio - overall_ratio) > 0.20:
                raise RuntimeError(
                    f"Class distribution drift detected for split '{split}' and class '{cls}': "
                    f"{split_ratio:.3f} vs overall {overall_ratio:.3f}"
                )

    return {split: sorted(data["indices"]) for split, data in split_assignments.items()}


def write_csv(out_path: Path, fieldnames: List[str], rows: Iterable[Dict[str, Any]]) -> None:
    """Запись строк (dict) в CSV-файл"""
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            # Замена None на пустые строки для CSV
            writer.writerow(
                {key: ("" if row.get(key) is None else row.get(key)) for key in fieldnames}
            )

# Основная функция сборки датасета
def build_dataset(input_dir: Path, output_dir: Path) -> None:
    cfg = load_cfg()
    feature_cols, _ = collect_schema(cfg)
    context = ExtractContext(cfg)

    rows: List[Dict[str, Any]] = []

    # 1. Итерация по файлам и извлечение признаков
    for gt_class, file_path in iter_dataset_files(input_dir):
        rel_path = file_path.relative_to(input_dir)
        sequence_id, orig_ext, curr_ext = parse_filename_metadata(file_path.name)
        
        # Вызов экстрактора для извлечения признаков
        features = extract_feats(str(file_path), cfg, context=context)

        row: Dict[str, Any] = {
            "path": str(rel_path).replace("\\", "/"),
            "gt_class": gt_class,
            "sequence_id": sequence_id,
            "orig_ext": orig_ext,
            "curr_ext": curr_ext,
        }
        row.update(features)
        rows.append(row)

    if not rows:
        raise RuntimeError("No files processed; dataset is empty.")

    # 2. Стратифицированное разделение
    splits = stratified_group_split(rows)
    output_dir.mkdir(parents=True, exist_ok=True)

    # 3. Запись результатов в CSV
    fieldnames = ["path", "gt_class", "sequence_id", "orig_ext", "curr_ext"] + feature_cols
    write_csv(output_dir / "dataset.csv", fieldnames, rows)

    for split, indices in splits.items():
        split_rows = [rows[i] for i in indices]
        write_csv(output_dir / f"{split}.csv", fieldnames, split_rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build dataset CSV with feature extraction.")
    parser.add_argument("input_dir", type=Path, help="Path to root directory with class subfolders.")
    parser.add_argument("output_dir", type=Path, help="Directory to store resulting CSV files.")
    args = parser.parse_args()

    build_dataset(args.input_dir, args.output_dir)


if __name__ == "__main__":
    main()