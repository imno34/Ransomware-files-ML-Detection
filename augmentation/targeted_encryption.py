'''
!!!WARNING!!! THIS CODE IS MARKED AS MALICIOUS BY MODERN AV SOFTWARE SINCE
DYNAMIC ANALYSIS SHOWS THAT PROGRAMM ENCRYPTS FILES WITH AES-GCM WHICH IS A RARE REAL-LIFE SCENARIO, I GUESS.
HOWEVER, THIS CODE IS BUILT FOR PURELY RESEARCH REASONS AND POSSESES NO EVIL WILL.
'''
# targeted_encryption.py
from __future__ import annotations

import argparse
import csv
import math
import random
import re
import shutil
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Sequence, Tuple

import yaml
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from featurizers.extract import ExtractContext, collect_schema, extract_feats, load_cfg
from training.dataset import build_group_id, build_pair_id, parse_filename_metadata

# Целевой класс для аугментированных строк.
TARGET_GT_CLASS = "ransomware-encrypted"

# Пороговые и блочные параметры алгоритмов.
TEN_MB = 10 * 1024 * 1024
TWENTY_MB = 20 * 1024 * 1024
BLOCK_64KB = 64 * 1024
CHUNK_16KB = 32 * 1024
HEADER_SMALL_BYTES = 16384

# Путь к конфигу и фиксированные параметры воспроизводимости/параллельности.
DEFAULT_SEED = 20240101
CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
CONFIG_FILE = CONFIG_DIR / "augmentation.yaml"
DEFAULT_WORKERS = 6
DEFAULT_CHUNKSIZE = 32

SUPPORTED_ALGORITHMS = ("header-only", "intermittent", "hybrid", "adaptive")
AUG_TOKEN_RE = re.compile(r"\b-?aug\b", flags=re.IGNORECASE)

_AUG_WORKER_CFG = None
_AUG_WORKER_CONTEXT = None


# Нормализация имени алгоритма и проверка поддержки.
def _normalize_algorithm_name(raw: str) -> str:
    key = str(raw).strip().lower()
    if key not in SUPPORTED_ALGORITHMS:
        raise ValueError("Unsupported alogithm")
    return key


# Проверка, что сумма долей строго равна 1.0.
def _validate_sum_to_one(name: str, values: Mapping[str, float]) -> None:
    total = sum(values.values())
    if not math.isclose(total, 1.0, rel_tol=0.0, abs_tol=1e-9):
        raise ValueError(f"{name} must sum to 1.0, got {total:.12f}")


# Загрузка алгоритмов и их квот из config/augmentation.yaml.
def load_algorithm_quotas() -> Dict[str, float]:
    if not CONFIG_FILE.is_file():
        raise FileNotFoundError(f"Config not found: {CONFIG_FILE}")

    with CONFIG_FILE.open("r", encoding="utf-8") as handle:
        cfg = yaml.safe_load(handle) or {}

    raw_algorithm_quotas = cfg.get("algorithm_quotas")
    if not isinstance(raw_algorithm_quotas, dict) or not raw_algorithm_quotas:
        raise ValueError("augmentation.yaml must define non-empty mapping 'algorithm_quotas'.")

    algorithm_quotas: Dict[str, float] = {}
    for algorithm, value in raw_algorithm_quotas.items():
        name = _normalize_algorithm_name(str(algorithm))
        try:
            ratio = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Quota for algorithm '{algorithm}' is not numeric: {value}"
            ) from exc
        if ratio < 0:
            raise ValueError(f"Quota for algorithm '{algorithm}' must be >= 0, got {ratio}")
        if name in algorithm_quotas:
            raise ValueError(f"Duplicate algorithm quota for '{name}'")
        algorithm_quotas[name] = ratio

    _validate_sum_to_one("algorithm_quotas", algorithm_quotas)
    return algorithm_quotas


# Добавление суффикса -aug перед текущим расширением файла.
def build_algorithm_suffix(algorithm_quotas: Mapping[str, float]) -> str:
    selected_algorithms = [alg for alg, quota in algorithm_quotas.items() if float(quota) > 0.0]
    if not selected_algorithms:
        raise ValueError("No algorithms with positive quota in 'algorithm_quotas'.")
    return "-".join(selected_algorithms)


def strip_aug_marker(extra: str) -> str:
    cleaned, substitutions = AUG_TOKEN_RE.subn("", extra)
    if substitutions <= 0:
        return extra
    cleaned = cleaned.strip("-")
    cleaned = re.sub(r"-{2,}", "-", cleaned)
    return cleaned


def build_pair_id_for_augmented(group_id: str, extra: str) -> str:
    if not extra:
        return group_id
    cleaned_extra = strip_aug_marker(extra)
    if not cleaned_extra:
        return group_id
    return build_pair_id(group_id, cleaned_extra)


def add_aug_suffix(filename: str) -> str:
    path = Path(filename)
    if path.suffix:
        return f"{path.stem}-aug{path.suffix}"
    return f"{path.name}-aug"


# Шифрование байтового блока AES-128-GCM (в файл записывается только ciphertext).
def encrypt_bytes_aes_gcm(plain: bytes, key: bytes) -> bytes:
    if not plain:
        return plain
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12))
    encrypted, _ = cipher.encrypt_and_digest(plain)
    return encrypted


def encrypt_region_in_place(handle, offset: int, length: int, key: bytes) -> int:
    if length <= 0:
        return 0
    handle.seek(offset)
    chunk = handle.read(length)
    if not chunk:
        return 0
    encrypted = encrypt_bytes_aes_gcm(chunk, key)
    handle.seek(offset)
    handle.write(encrypted)
    return len(chunk)


def apply_header_only(file_path: Path, key: bytes) -> None:
    size = file_path.stat().st_size
    if size <= 0:
        return
    header_size = BLOCK_64KB if size > TWENTY_MB else HEADER_SMALL_BYTES
    with file_path.open("r+b") as handle:
        encrypt_region_in_place(handle, 0, min(header_size, size), key)


def apply_intermittent(file_path: Path, key: bytes) -> None:
    size = file_path.stat().st_size
    if size <= 0:
        return
    with file_path.open("r+b") as handle:
        offset = BLOCK_64KB
        while offset < size:
            length = min(CHUNK_16KB, size - offset)
            encrypt_region_in_place(handle, offset, length, key)
            offset += BLOCK_64KB


def apply_hybrid(file_path: Path, key: bytes) -> None:
    size = file_path.stat().st_size
    if size <= 0:
        return
    header_size = BLOCK_64KB if size > TWENTY_MB else HEADER_SMALL_BYTES
    with file_path.open("r+b") as handle:
        head_len = min(header_size, size)
        encrypt_region_in_place(handle, 0, head_len, key)
        offset = head_len
        while offset < size:
            length = min(CHUNK_16KB, size - offset)
            encrypt_region_in_place(handle, offset, length, key)
            offset += BLOCK_64KB


def apply_adaptive(file_path: Path, key: bytes) -> None:
    size = file_path.stat().st_size
    if size <= 0:
        return
    if size > TEN_MB:
        apply_hybrid(file_path, key)
        return
    with file_path.open("r+b") as handle:
        encrypt_region_in_place(handle, 0, size, key)


# Маршрутизация вызова нужного алгоритма аугментации.
def apply_algorithm(file_path: Path, algorithm: str) -> None:
    key = get_random_bytes(16)
    if algorithm == "header-only":
        apply_header_only(file_path, key)
    elif algorithm == "intermittent":
        apply_intermittent(file_path, key)
    elif algorithm == "hybrid":
        apply_hybrid(file_path, key)
    elif algorithm == "adaptive":
        apply_adaptive(file_path, key)
    else:
        raise ValueError("Unsupported alogithm")


# Дискретное распределение N файлов по квотам алгоритмов:
# floor + раздача остатка по наибольшей дробной части.
def allocate_algorithm_counts(total: int, algorithm_quotas: Mapping[str, float]) -> Dict[str, int]:
    counts: Dict[str, int] = {alg: 0 for alg in algorithm_quotas}
    if total <= 0:
        return counts

    desired = {alg: total * ratio for alg, ratio in algorithm_quotas.items()}
    floors = {alg: int(math.floor(desired[alg])) for alg in algorithm_quotas}
    for alg in algorithm_quotas:
        counts[alg] = floors[alg]

    remainder = total - sum(counts.values())
    if remainder <= 0:
        return counts

    order = sorted(
        algorithm_quotas.keys(),
        key=lambda alg: desired[alg] - floors[alg],
        reverse=True,
    )
    for alg in order[:remainder]:
        counts[alg] += 1
    return counts


# Формирование плана обработки: индекс файла -> выбранный алгоритм.
def build_algorithm_plan(
    file_indices: Sequence[int],
    algorithm_quotas: Mapping[str, float],
) -> List[Tuple[int, str]]:
    counts = allocate_algorithm_counts(len(file_indices), algorithm_quotas)
    plan: List[Tuple[int, str]] = []
    cursor = 0
    for algorithm in algorithm_quotas.keys():
        count = counts[algorithm]
        if count <= 0:
            continue
        chunk = file_indices[cursor : cursor + count]
        cursor += count
        for idx in chunk:
            plan.append((int(idx), algorithm))
    return plan


def write_csv(path: Path, fieldnames: Sequence[str], rows: Iterable[Mapping[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: ("" if row.get(key) is None else row.get(key)) for key in fieldnames})


def _init_aug_worker() -> None:
    global _AUG_WORKER_CFG, _AUG_WORKER_CONTEXT
    _AUG_WORKER_CFG = load_cfg()
    _AUG_WORKER_CONTEXT = ExtractContext(_AUG_WORKER_CFG)


def _build_augmented_row(task: tuple[str, str, str, str]) -> Dict[str, Any]:
    file_path_str, algorithm, rel_folder, aug_parent = task
    file_path = Path(file_path_str)

    sequence_id, orig_ext, extra, curr_ext = parse_filename_metadata(file_path.name, TARGET_GT_CLASS)
    group_id = build_group_id(sequence_id, orig_ext, file_path.name)
    pair_id = build_pair_id_for_augmented(group_id, extra or "")
    feats = extract_feats(
        file_path_str,
        _AUG_WORKER_CFG,
        context=_AUG_WORKER_CONTEXT,
        fallback=True,
    )

    # Path в .csv берется относительно новой папки, чтобы не дублировать с исходниками для аугментации
    rel_prefix = Path(rel_folder)
    row: Dict[str, Any] = {
        "path": str(rel_prefix / file_path.name).replace("\\", "/"),
        "gt_class": TARGET_GT_CLASS,
        "sequence_id": sequence_id,
        "orig_ext": orig_ext,
        "extra": extra,
        "curr_ext": curr_ext,
        "group_id": group_id,
        "pair_id": pair_id,
        "is_augmented": True,
        "aug_encryption": algorithm,
        "aug_parent": aug_parent,
    }
    row.update(feats)
    return row


def build_augmented_rows(
    items: Sequence[MutableMapping[str, Any]],
    output_dir: Path,
    folder_name: str,
    csv_name: str,
) -> List[Dict[str, Any]]:
    cfg = load_cfg()
    feature_cols, _ = collect_schema(cfg)
    rel_folder = str((Path("augmented") / folder_name).as_posix())
    tasks = [
        (
            str(Path(item["aug_path"])),
            str(item["algorithm"]),
            rel_folder,
            str(item["aug_parent"]),
        )
        for item in items
    ]

    if tasks:
        with ProcessPoolExecutor(
            max_workers=DEFAULT_WORKERS,
            initializer=_init_aug_worker,
        ) as executor:
            rows = list(executor.map(_build_augmented_row, tasks, chunksize=DEFAULT_CHUNKSIZE))
    else:
        rows = []

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

    write_csv(output_dir / csv_name, fieldnames, rows)
    return rows


def copy_source_files(files_to_augment_dir: Path, augmented_files_dir: Path) -> List[Path]:
    copied: List[Path] = []
    for src_path in sorted(files_to_augment_dir.iterdir()):
        if not src_path.is_file():
            continue
        dst_path = augmented_files_dir / src_path.name
        shutil.copy2(src_path, dst_path)
        copied.append(dst_path)
    return copied


def main() -> None:
    parser = argparse.ArgumentParser(description="Targeted encryption for prepared augmentation files.")
    parser.add_argument(
        "--fdir",
        type=Path,
        required=True,
        help="Path to directory with files selected for augmentation.",
    )
    parser.add_argument(
        "--odir",
        type=Path,
        required=True,
        help="Output directory where augmented_files-* and aug-*.csv will be stored.",
    )
    args = parser.parse_args()

    files_to_augment_dir = args.fdir.resolve()
    if not files_to_augment_dir.is_dir():
        raise FileNotFoundError(f"Input directory not found: {files_to_augment_dir}")

    output_dir = args.odir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    algorithm_quotas = load_algorithm_quotas()
    algorithm_suffix = build_algorithm_suffix(algorithm_quotas)
    augmented_folder_name = f"augmented_files-{algorithm_suffix}"
    augmented_csv_name = f"aug-{algorithm_suffix}.csv"
    augmented_files_dir = output_dir / augmented_folder_name
    augmented_files_dir.mkdir(parents=True, exist_ok=True)

    # 1) Копирование всех файлов в output_dir/augmented_files.
    copied_files = copy_source_files(files_to_augment_dir, augmented_files_dir)

    rng = random.Random(DEFAULT_SEED)
    file_indices = list(range(len(copied_files)))
    rng.shuffle(file_indices)
    plan = build_algorithm_plan(file_indices, algorithm_quotas)
    algorithm_counts: Dict[str, int] = {alg: 0 for alg in algorithm_quotas}

    # 2) Применение алгоритмов к файлам в augmented_files и переименование с суффиксом -aug.
    processed_items: List[MutableMapping[str, Any]] = []
    for file_idx, algorithm in plan:
        src_path = copied_files[file_idx]
        src_sequence_id, src_orig_ext, src_extra, _ = parse_filename_metadata(src_path.name, "benign")
        src_group_id = build_group_id(src_sequence_id, src_orig_ext, src_path.name)
        src_pair_id = build_pair_id(src_group_id, src_extra)

        aug_name = add_aug_suffix(src_path.name)
        aug_path = src_path.with_name(aug_name)
        src_path.rename(aug_path)
        apply_algorithm(aug_path, algorithm)
        algorithm_counts[algorithm] += 1

        processed_items.append(
            {
                "aug_path": str(aug_path),
                "algorithm": algorithm,
                "aug_parent": src_pair_id,
            }
        )

    # 3) Парсинг файлов из augmented_files в augmented_set.csv.
    build_augmented_rows(
        processed_items,
        output_dir,
        folder_name=augmented_folder_name,
        csv_name=augmented_csv_name,
    )

    print(f"Input files: {len(copied_files)}")
    print(f"Encrypted files: {len(processed_items)}")
    print(f"Algorithm counts: {algorithm_counts}")
    print(f"Augmented files dir: {augmented_files_dir}")
    print(f"Augmented CSV: {output_dir / augmented_csv_name}")
    print(f"Artifacts: {output_dir}")


if __name__ == "__main__":
    main()
