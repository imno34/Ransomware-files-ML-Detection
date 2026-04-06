'''
!!!WARNING!!! THIS CODE IS MARKED AS MALICIOUS BY MODERN AV SOFTWARE SINCE
DYNAMIC ANALYSIS SHOWS THAT PROGRAMM ENCRYPTS FILES WITH AES-GCM WHICH IS A RARE REAL-LIFE SCENARIO, I GUESS.
HOWEVER, THIS CODE IS BUILT FOR PURELY RESEARCH REASONS AND POSSESES NO EVIL WILL.
'''
# initial_split.py
from __future__ import annotations

import argparse
import math
import random
import shutil
from pathlib import Path
from typing import Dict, List, Mapping, Sequence

import pandas as pd
import yaml

# Разрешенные исходные классы для формирования augmentation pool.
ALLOWED_GT_CLASSES = {"benign", "benign-encrypted"}

# Фиксированный seed для воспроизводимого отбора.
DEFAULT_SEED = 20240101

# Путь к конфигу аугментации.
CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
CONFIG_FILE = CONFIG_DIR / "augmentation.yaml"


# Валидация доли из диапазона [0, 1].
def _require_fraction(value: float, name: str) -> float:
    if value < 0.0 or value > 1.0:
        raise ValueError(f"{name} must be in [0, 1], got {value}")
    return float(value)


# Проверка, что сумма долей строго равна 1.0.
def _validate_sum_to_one(name: str, values: Mapping[str, float]) -> None:
    total = sum(values.values())
    if not math.isclose(total, 1.0, rel_tol=0.0, abs_tol=1e-9):
        raise ValueError(f"{name} must sum to 1.0, got {total:.12f}")


# Загрузка квот расширений из config/augmentation.yaml.
def load_orig_ext_quotas() -> Dict[str, float]:
    if not CONFIG_FILE.is_file():
        raise FileNotFoundError(f"Config not found: {CONFIG_FILE}")

    with CONFIG_FILE.open("r", encoding="utf-8") as handle:
        cfg = yaml.safe_load(handle) or {}

    raw_quotas = cfg.get("orig_ext_quotas")
    if not isinstance(raw_quotas, dict) or not raw_quotas:
        raise ValueError("augmentation.yaml must define non-empty mapping 'orig_ext_quotas'.")

    quotas: Dict[str, float] = {}
    for ext, value in raw_quotas.items():
        key = str(ext).strip().lower()
        if not key:
            raise ValueError("Found empty extension key in orig_ext_quotas.")
        try:
            ratio = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Quota for extension '{ext}' is not numeric: {value}") from exc
        if ratio < 0:
            raise ValueError(f"Quota for extension '{ext}' must be >= 0, got {ratio}")
        quotas[key] = ratio

    _validate_sum_to_one("orig_ext_quotas", quotas)
    return quotas


# Создание директорий для исходной выборки под аугментацию.
def ensure_augmented_dirs(input_csv: Path) -> tuple[Path, Path]:
    augmented_dir = input_csv.resolve().parent / "augmented"
    files_to_augment_dir = augmented_dir / "files_to_augment"
    files_to_augment_dir.mkdir(parents=True, exist_ok=True)
    return augmented_dir, files_to_augment_dir


# Расчет целевого числа файлов как доли от общего количества.
def compute_target_count(total: int, fraction: float) -> int:
    if total <= 0 or fraction <= 0:
        return 0
    raw = int(round(total * fraction))
    return max(1, min(total, raw))


def allocate_by_quota(
    candidates_by_ext: Mapping[str, Sequence[int]],
    quotas: Mapping[str, float],
    target: int,
) -> Dict[str, int]:
    # Первичное распределение по квотам расширений.
    alloc: Dict[str, int] = {ext: 0 for ext in quotas}
    if target <= 0:
        return alloc

    desired = {ext: target * quotas[ext] for ext in quotas}
    floors = {ext: int(math.floor(desired[ext])) for ext in quotas}
    for ext in quotas:
        alloc[ext] = min(len(candidates_by_ext.get(ext, [])), floors[ext])

    remaining = target - sum(alloc.values())
    if remaining <= 0:
        return alloc

    remainder_order = sorted(
        quotas.keys(),
        key=lambda ext: (desired[ext] - floors[ext], quotas[ext]),
        reverse=True,
    )
    for ext in remainder_order:
        if remaining <= 0:
            break
        capacity = len(candidates_by_ext.get(ext, []))
        spare = capacity - alloc[ext]
        if spare <= 0:
            continue
        take = min(spare, remaining)
        alloc[ext] += take
        remaining -= take

    if remaining <= 0:
        return alloc

    # Если после дробных остатков дефицит сохранился, добираем по доступной емкости.
    by_capacity = sorted(
        quotas.keys(),
        key=lambda ext: (len(candidates_by_ext.get(ext, [])) - alloc[ext], quotas[ext]),
        reverse=True,
    )
    for ext in by_capacity:
        if remaining <= 0:
            break
        capacity = len(candidates_by_ext.get(ext, []))
        spare = capacity - alloc[ext]
        if spare <= 0:
            continue
        take = min(spare, remaining)
        alloc[ext] += take
        remaining -= take

    return alloc


def sample_pool_by_quota(
    pool_df: pd.DataFrame,
    quotas: Mapping[str, float],
    target_count: int,
    rng: random.Random,
) -> pd.DataFrame:
    # Выборка поднабора файлов с учетом квот по расширениям.
    if target_count <= 0 or pool_df.empty:
        return pool_df.iloc[0:0].copy()

    grouped_indices: Dict[str, List[int]] = {ext: [] for ext in quotas}
    for idx, ext in zip(pool_df.index, pool_df["orig_ext_norm"]):
        if ext in grouped_indices:
            grouped_indices[ext].append(int(idx))

    for ext in grouped_indices:
        rng.shuffle(grouped_indices[ext])

    alloc = allocate_by_quota(grouped_indices, quotas, target_count)
    picked_indices: List[int] = []
    for ext, count in alloc.items():
        if count > 0:
            picked_indices.extend(grouped_indices.get(ext, [])[:count])

    picked_indices = list(dict.fromkeys(picked_indices))
    if len(picked_indices) > target_count:
        rng.shuffle(picked_indices)
        picked_indices = picked_indices[:target_count]

    if len(picked_indices) < target_count:
        selected = set(picked_indices)
        residue = [int(i) for i in pool_df.index if int(i) not in selected]
        rng.shuffle(residue)
        need = target_count - len(picked_indices)
        picked_indices.extend(residue[:need])

    return pool_df.loc[picked_indices].copy()


# Поиск исходного файла:
# 1) files_root / относительный path из CSV, 2) fallback по basename.
def resolve_source_path(files_root: Path, row_path: str) -> Path:
    rel = Path(str(row_path).replace("\\", "/"))
    candidate = files_root / rel
    if candidate.is_file():
        return candidate
    fallback = files_root / rel.name
    if fallback.is_file():
        return fallback
    raise FileNotFoundError(f"Unable to resolve source file: row path='{row_path}', root='{files_root}'")


def main() -> None:
    parser = argparse.ArgumentParser(description="Initial split for augmentation files.")
    parser.add_argument(
        "--incsv",
        type=Path,
        required=True,
        help="Path to input parsed CSV.",
    )
    parser.add_argument(
        "--froot",
        type=Path,
        required=True,
        help="Root directory that contains source files from CSV paths.",
    )
    parser.add_argument(
        "--pool-fraction",
        type=float,
        required=True,
        help="Fraction [0,1] of extension-filtered augmentation pool to sample.",
    )
    args = parser.parse_args()

    pool_fraction = _require_fraction(args.pool_fraction, "--pool-fraction")
    ext_quotas = load_orig_ext_quotas()

    input_csv = args.incsv.resolve()
    if not input_csv.is_file():
        raise FileNotFoundError(f"Input CSV not found: {input_csv}")
    files_root = args.froot.resolve()
    if not files_root.is_dir():
        raise FileNotFoundError(f"Files root directory not found: {files_root}")

    rng = random.Random(DEFAULT_SEED)
    df = pd.read_csv(input_csv)
    for required in ("path", "gt_class", "orig_ext"):
        if required not in df.columns:
            raise ValueError(f"Input CSV must contain column '{required}'")

    # 1) Формирование augmentation pool: только benign/benign-encrypted.
    pool_df = df[df["gt_class"].isin(ALLOWED_GT_CLASSES)].copy()
    # 2) Фильтрация по расширениям из orig_ext_quotas.
    pool_df["orig_ext_norm"] = pool_df["orig_ext"].fillna("").astype(str).str.lower()
    pool_df = pool_df[pool_df["orig_ext_norm"].isin(set(ext_quotas.keys()))].copy()

    # 3) Квотный отбор до заданной доли augmentation pool.
    sampled_target = compute_target_count(len(pool_df), pool_fraction)
    sampled_df = sample_pool_by_quota(pool_df, ext_quotas, sampled_target, rng)

    # 4) Создание каталога augmented/files_to_augment.
    augmented_root, files_to_augment_dir = ensure_augmented_dirs(input_csv)

    # 5) Копирование выбранных файлов в files_to_augment без изменений.
    copied = 0
    for _, row in sampled_df.iterrows():
        src_path = resolve_source_path(files_root, str(row["path"]))
        dst_path = files_to_augment_dir / src_path.name
        shutil.copy2(src_path, dst_path)
        copied += 1

    print(f"Input rows: {len(df)}")
    print(f"Eligible pool rows: {len(pool_df)}")
    print(f"Sampled by quotas: {len(sampled_df)}")
    print(f"Copied files: {copied}")
    print(f"Artifacts: {augmented_root}")


if __name__ == "__main__":
    main()
