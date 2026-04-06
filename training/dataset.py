#dataset.py
from __future__ import annotations

import argparse
import csv
import os
import random
import sys
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

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
DEFAULT_WORKERS = 6
DEFAULT_CHUNKSIZE = 32
MAX_CLASS_RATIO_DRIFT = 0.20

_WORKER_CFG = None
_WORKER_CONTEXT = None
_WORKER_FALLBACK = False


def parse_filename_metadata_default(
    name: str,
) -> Tuple[Optional[int], Optional[str], Optional[str], Optional[str]]:
    """Разобрать имя файла для классов benign и benign-encrypted."""
    first_dash = name.find("-")
    last_dot = name.rfind(".")
    if first_dash <= 0 or last_dot <= first_dash + 1 or last_dot >= len(name) - 1:
        return None, None, None, None

    seq_part = name[:first_dash]
    try:
        sequence_id = int(seq_part)
    except ValueError:
        return None, None, None, None

    payload = name[first_dash + 1 : last_dot]
    curr_ext = name[last_dot + 1 :]
    if not payload or not curr_ext:
        return None, None, None, None

    split_positions = [idx for idx in (payload.find("-"), payload.find(".")) if idx != -1]
    if split_positions:
        boundary = min(split_positions)
        orig_ext = payload[:boundary]
        extra = payload[boundary + 1 :]
    else:
        orig_ext = payload
        extra = ""

    if not orig_ext:
        return None, None, None, None

    return sequence_id, orig_ext, extra, curr_ext


def parse_filename_metadata_ransomware(
    name: str,
) -> Tuple[Optional[int], Optional[str], Optional[str], Optional[str]]:
    """Разобрать маску ransomware-encrypted:
    sequence_id-orig_ext-extra.orig_ext.curr_ext
    """
    first_dash = name.find("-")
    if first_dash <= 0 or first_dash >= len(name) - 1:
        return None, None, None, None

    seq_part = name[:first_dash]
    try:
        sequence_id = int(seq_part)
    except ValueError:
        return None, None, None, None

    tail = name[first_dash + 1 :]
    if not tail:
        return None, None, None, None

    sep_pos = -1
    sep_char = ""
    for idx, ch in enumerate(tail):
        if ch in ("-", "."):
            sep_pos = idx
            sep_char = ch
            break

    if sep_pos <= 0:
        return None, None, None, None

    orig_ext = tail[:sep_pos]
    if not orig_ext:
        return None, None, None, None

    if sep_char == ".":
        extra = ""
        curr_ext = tail[sep_pos + 1 :]
        if not curr_ext:
            return None, None, None, None
        return sequence_id, orig_ext, extra, curr_ext

    # sep_char == "-": выделить extra до первой точки и взять curr_ext как остаток
    dot_after_extra = tail.find(".", sep_pos + 1)
    if dot_after_extra <= sep_pos + 1:
        return None, None, None, None

    extra = tail[sep_pos + 1 : dot_after_extra]
    if not extra:
        return None, None, None, None

    curr_ext = tail[dot_after_extra + 1 :]
    if not curr_ext:
        return None, None, None, None

    return sequence_id, orig_ext, extra, curr_ext


def parse_filename_metadata(
    name: str, gt_class: str
) -> Tuple[Optional[int], Optional[str], Optional[str], Optional[str]]:
    """Разобрать имя файла по маске, зависящей от класса."""
    if gt_class == "ransomware-encrypted":
        return parse_filename_metadata_ransomware(name)
    return parse_filename_metadata_default(name)

def build_group_id(sequence_id: Optional[int], orig_ext: Optional[str], fallback_name: str) -> str:
    # Построить ключ группы для сплита; при некорректной маске использовать имя файла
    if sequence_id is None or not orig_ext:
        return fallback_name
    return f"{sequence_id}-{orig_ext}"


def build_pair_id(group_id: str, extra: Optional[str]) -> str:
    if extra:
        return f"{group_id}-{extra}"
    return group_id


def iter_dataset_files(input_dir: Path) -> Iterable[Tuple[str, Path]]:
    # Вернуть пары (gt_class, path) для всех файлов в известных папках классов
    for class_name, folder in ROOT_FOLDERS.items():
        class_dir = input_dir / folder
        if not class_dir.is_dir():
            continue
        for path in class_dir.rglob("*"):
            if path.is_file():
                yield class_name, path


def stratified_group_split(rows: List[Dict[str, Any]]) -> Dict[str, List[int]]:
    # Разбить строки по group_id на train/valid/test с учетом баланса по классам
    group_to_indices: Dict[str, List[int]] = defaultdict(list)
    group_class_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    class_to_groups: Dict[str, Set[str]] = defaultdict(set)
    total_class_counts: Dict[str, int] = defaultdict(int)

    for idx, row in enumerate(rows):
        group_id = str(row["group_id"])
        cls = str(row["gt_class"])
        group_to_indices[group_id].append(idx)
        group_class_counts[group_id][cls] += 1
        class_to_groups[cls].add(group_id)
        total_class_counts[cls] += 1

    # Инициализация структур для хранения разделения
    split_assignments = {
        split: {
            "group_ids": set(),
            "indices": set(),
            "class_counts": defaultdict(int),
            "class_group_counts": defaultdict(int),
            "total": 0,
        }
        for split in SPLIT_RATIOS
    }

    rng = random.Random(RANDOM_SEED)
    split_names = list(SPLIT_RATIOS.keys())
    all_group_ids = list(group_to_indices.keys())
    unassigned_groups = set(all_group_ids)
    target_total_rows = {split: SPLIT_RATIOS[split] * len(rows) for split in split_names}
    target_class_rows = {
        split: {cls: SPLIT_RATIOS[split] * total_class_counts[cls] for cls in total_class_counts}
        for split in split_names
    }

    def assign_group(group_id: str, split: str) -> None:
        # Назначить одну целую группу group_id в сплит и обновить счетчики
        if group_id not in unassigned_groups:
            return
        unassigned_groups.remove(group_id)
        split_assignments[split]["group_ids"].add(group_id)
        split_assignments[split]["indices"].update(group_to_indices[group_id])
        split_assignments[split]["total"] += len(group_to_indices[group_id])
        for cls, count in group_class_counts[group_id].items():
            split_assignments[split]["class_counts"][cls] += count
            split_assignments[split]["class_group_counts"][cls] += 1

    def choose_best_split(group_id: str) -> str:
        # Выбрать сплит, который минимально переполняет целевые квоты по общему объему и классам
        group_size = len(group_to_indices[group_id])
        scores: List[Tuple[float, float, float, str]] = []
        for split in split_names:
            total_target = max(1.0, target_total_rows[split])
            total_after = split_assignments[split]["total"] + group_size
            total_fill_after = total_after / total_target

            class_fill_after_values: List[float] = []
            for cls, incoming_count in group_class_counts[group_id].items():
                target_count = max(1.0, target_class_rows[split][cls])
                current_count = split_assignments[split]["class_counts"][cls]
                class_fill_after_values.append((current_count + incoming_count) / target_count)

            """Поддерживать пропорциональный прогресс каждого сплита по целевому
            общему размеру и целевым счетчикам классов. Это предотвращает раннее
            переполнение valid/test, когда датасет доминируется benign-группами."""

            peak_fill_after = max([total_fill_after] + class_fill_after_values)
            avg_fill_after = (
                total_fill_after + sum(class_fill_after_values)
            ) / (1 + len(class_fill_after_values))

            scores.append((peak_fill_after, avg_fill_after, total_fill_after, split))

        scores.sort()
        return scores[0][3]

    for cls in sorted(class_to_groups):
        candidate_groups = list(class_to_groups[cls])
        if len(candidate_groups) < len(split_names):
            continue

        rng.shuffle(candidate_groups)
        candidate_groups.sort(
            key=lambda group_id: (
                -len(group_class_counts[group_id]),
                len(group_to_indices[group_id]),
                group_id,
            )
        )

        for split in split_names:
            if split_assignments[split]["class_group_counts"][cls] > 0:
                continue
            group_id = next((gid for gid in candidate_groups if gid in unassigned_groups), None)
            if group_id is None:
                break
            assign_group(group_id, split)

    remaining_groups = list(unassigned_groups)
    rng.shuffle(remaining_groups)
    remaining_groups.sort(
        key=lambda group_id: (
            -len(group_class_counts[group_id]),
            -len(group_to_indices[group_id]),
            group_id,
        )
    )
    for group_id in remaining_groups:
        assign_group(group_id, choose_best_split(group_id))

    all_indices = set()
    all_assigned_group_ids = set()
    for split, data in split_assignments.items():
        overlap_indices = all_indices & data["indices"]
        if overlap_indices:
            raise RuntimeError(f"Groups assigned to multiple splits: {overlap_indices}")
        all_indices.update(data["indices"])

        overlap_groups = all_assigned_group_ids & data["group_ids"]
        if overlap_groups:
            raise RuntimeError(f"group_id assigned to multiple splits: {sorted(overlap_groups)}")
        all_assigned_group_ids.update(data["group_ids"])

    if len(all_indices) != len(rows):
        missing = set(range(len(rows))) - all_indices
        raise RuntimeError(f"Missing assignments for indices: {missing}")

    if all_assigned_group_ids != set(all_group_ids):
        missing_groups = sorted(set(all_group_ids) - all_assigned_group_ids)
        raise RuntimeError(f"Missing assignments for group_id values: {missing_groups}")

    for cls, groups in class_to_groups.items():
        if len(groups) < len(split_names):
            continue
        for split, data in split_assignments.items():
            if data["class_group_counts"][cls] <= 0:
                raise RuntimeError(
                    f"Split '{split}' does not contain any group for class '{cls}'"
                )

    total_rows = len(rows)
    overall_class_ratio = {
        cls: total_class_counts[cls] / total_rows for cls in total_class_counts
    }
    for split, data in split_assignments.items():
        split_total = max(1, data["total"])
        for cls, overall_ratio in overall_class_ratio.items():
            split_ratio = data["class_counts"][cls] / split_total
            if abs(split_ratio - overall_ratio) > MAX_CLASS_RATIO_DRIFT:
                raise RuntimeError(
                    f"Class distribution drift detected for split '{split}' and class '{cls}': "
                    f"{split_ratio:.3f} vs overall {overall_ratio:.3f}"
                )

    return {split: sorted(data["indices"]) for split, data in split_assignments.items()}


def write_csv(out_path: Path, fieldnames: List[str], rows: Iterable[Dict[str, Any]]) -> None:
    # Запись строк (dict) в CSV-файл
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            # Замена None на пустые строки для CSV
            writer.writerow(
                {key: ("" if row.get(key) is None else row.get(key)) for key in fieldnames}
            )


def _init_worker(fallback: bool = False) -> None:
    # Для каждого воркера файл конфигурации подгружается единожды
    global _WORKER_CFG, _WORKER_CONTEXT, _WORKER_FALLBACK
    _WORKER_CFG = load_cfg()
    _WORKER_CONTEXT = ExtractContext(_WORKER_CFG)
    _WORKER_FALLBACK = bool(fallback)


def _extract_row(task: Tuple[str, str, str]) -> Dict[str, Any]:
    # Определение задачи воркера: собирает метаданные, собирает признаки и, следовательно, формирует строку датасета
    gt_class, input_dir_str, file_path_str = task
    input_dir = Path(input_dir_str)
    file_path = Path(file_path_str)

    rel_path = file_path.relative_to(input_dir)
    sequence_id, orig_ext, extra, curr_ext = parse_filename_metadata(file_path.name, gt_class)
    group_id = build_group_id(sequence_id, orig_ext, file_path.name)
    pair_id = build_pair_id(group_id, extra)
    features = extract_feats(
        file_path_str,
        _WORKER_CFG,
        context=_WORKER_CONTEXT,
        fallback=_WORKER_FALLBACK,
    )

    row: Dict[str, Any] = {
        "path": str(rel_path).replace("\\", "/"),
        "gt_class": gt_class,
        "sequence_id": sequence_id,
        "orig_ext": orig_ext,
        "extra": extra,
        "curr_ext": curr_ext,
        "group_id": group_id,
        "pair_id": pair_id,
        "is_augmented": False,
        "aug_encryption": None,
        "aug_parent": None,
    }
    row.update(features)
    return row


def build_dataset(
    input_dir: Path,
    output_dir: Path,
    workers: int = DEFAULT_WORKERS,
    chunksize: int = DEFAULT_CHUNKSIZE,
    fallback: bool = False,
) -> None:
    total_start = time.perf_counter()

    cfg = load_cfg()
    feature_cols, _ = collect_schema(cfg)

    # Построение списка задач (порядок входа определяется в executor.map).
    scan_start = time.perf_counter()
    file_tasks = [
        (gt_class, str(input_dir), str(file_path))
        for gt_class, file_path in iter_dataset_files(input_dir)
    ]
    scan_elapsed = time.perf_counter() - scan_start

    if not file_tasks:
        raise RuntimeError("No files processed; dataset is empty.")

    worker_count = max(1, workers)
    max_workers = os.cpu_count() or worker_count
    worker_count = min(worker_count, max_workers)

    # Запуск экстрактора в пуле процессов
    extract_start = time.perf_counter()
    with ProcessPoolExecutor(
        max_workers=worker_count,
        initializer=_init_worker,
        initargs=(bool(fallback),),
    ) as executor:
        rows = list(executor.map(_extract_row, file_tasks, chunksize=max(1, chunksize)))
    extract_elapsed = time.perf_counter() - extract_start

    # Стратифицированное разбиение
    split_start = time.perf_counter()
    splits = stratified_group_split(rows)
    split_elapsed = time.perf_counter() - split_start

    # Запись результатов в CSV
    write_start = time.perf_counter()
    output_dir.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "path",
        "gt_class",
        "sequence_id",
        "orig_ext",
        "extra",
        "curr_ext",
        "group_id",
        "pair_id",
        "is_augmented",
        "aug_encryption",
        "aug_parent",
    ] + feature_cols
    write_csv(output_dir / "dataset.csv", fieldnames, rows)

    for split, indices in splits.items():
        split_rows = [rows[i] for i in indices]
        write_csv(output_dir / f"{split}.csv", fieldnames, split_rows)
    write_elapsed = time.perf_counter() - write_start

    total_elapsed = time.perf_counter() - total_start

    print(f"Files discovered: {len(file_tasks)}")
    print(f"Workers used: {worker_count}")
    print(f"Chunksize: {max(1, chunksize)}")
    print(f"Time scan: {scan_elapsed:.3f}s")
    print(f"Time extract: {extract_elapsed:.3f}s")
    print(f"Time split: {split_elapsed:.3f}s")
    print(f"Time write: {write_elapsed:.3f}s")
    print(f"Time total: {total_elapsed:.3f}s")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build dataset CSV with feature extraction.")
    parser.add_argument(
        "--idir",
        type=Path,
        required=True,
        help="Path to root directory with class subfolders.",
    )
    parser.add_argument(
        "--odir",
        type=Path,
        required=True,
        help="Directory to store resulting CSV files.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Number of worker processes for feature extraction (default: {DEFAULT_WORKERS}).",
    )
    parser.add_argument(
        "--chunksize",
        type=int,
        default=DEFAULT_CHUNKSIZE,
        help=f"Task batch size passed to ProcessPoolExecutor.map (default: {DEFAULT_CHUNKSIZE}).",
    )
    parser.add_argument(
        "--fallback",
        action="store_true",
        help="Enable format fallback checks (PDF/OOXML) when magic detection fails.",
    )
    args = parser.parse_args()

    build_dataset(
        args.idir,
        args.odir,
        workers=args.workers,
        chunksize=args.chunksize,
        fallback=args.fallback,
    )


if __name__ == "__main__":
    main()
