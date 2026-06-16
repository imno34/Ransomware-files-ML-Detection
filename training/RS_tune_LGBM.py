from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Dict, Iterable, List, Mapping

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from joblib import Parallel, delayed
from lightgbm import LGBMClassifier
from scipy.stats import randint, uniform
from sklearn.metrics import f1_score, recall_score
from sklearn.model_selection import ParameterSampler, StratifiedGroupKFold

import vectorize


LABELS = sorted(vectorize.LABEL_MAP.values())
RANSOMWARE_LABEL = int(vectorize.LABEL_MAP["ransomware-encrypted"])

N_ITER = 100
N_SPLITS = 5
RANDOM_STATE = 42
LGBM_N_ESTIMATORS = 2000
LGBM_N_JOBS = 1
LGBM_SUBSAMPLE_FREQ = 1

TRIALS_FILENAME = "random_search_trials.csv"
HISTORY_PLOT_FILENAME = "optimization_history_lgbm.png"
NUM_LEAVES_MIN_CHILD_HEATMAP_FILENAME = "num_leaves_min_child_samples_heatmap.png"
LEARNING_RATE_NUM_LEAVES_HEATMAP_FILENAME = "learning_rate_num_leaves_heatmap.png"
MAX_DEPTH_NUM_LEAVES_HEATMAP_FILENAME = "max_depth_num_leaves_heatmap.png"
SUBSAMPLE_COLSAMPLE_HEATMAP_FILENAME = "subsample_colsample_bytree_heatmap.png"
SPEARMAN_HEATMAP_FILENAME = "spearman_correlation_heatmap.png"

PARAM_DISTRIBUTIONS = {
    "num_leaves": randint(20, 150),
    "min_child_samples": randint(10, 100),
    "subsample": uniform(0.6, 0.4),
    "colsample_bytree": uniform(0.6, 0.4),
    "max_depth": [3, 5, 7, 10, -1],
    "learning_rate": [0.01, 0.03, 0.05, 0.1],
}

NUM_LEAVES_BIN_EDGES = [15, 32, 64, 128, 150]
NUM_LEAVES_BIN_LABELS = [
    "16-32\nlow complexity",
    "33-64\nmoderate complexity",
    "65-128\nhigh complexity",
    "129-150\nvery high complexity",
]

MIN_CHILD_BIN_EDGES = [9, 30, 60, 100]
MIN_CHILD_BIN_LABELS = [
    "10-30\nweak regularization",
    "31-60\nmoderate regularization",
    "61-100\nstrong regularization",
]

LEARNING_RATE_LABELS = ["0.01", "0.03", "0.05", "0.10"]

MAX_DEPTH_LABELS = ["3", "5", "7", "10", "-1\nunlimited"]

SUBSAMPLE_BIN_EDGES = [0.6, 0.7, 0.8, 0.9, 1.0]
SUBSAMPLE_BIN_LABELS = ["0.60-0.70", "0.70-0.80", "0.80-0.90", "0.90-1.00"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Random Search tuning for LightGBM with StratifiedGroupKFold."
    )
    parser.add_argument(
        "--trn",
        "--train-split",
        "--train-csv",
        dest="train_csv",
        type=Path,
        required=True,
        help="Path to train CSV.",
    )
    parser.add_argument(
        "--odir",
        type=Path,
        required=True,
        help="Directory to store tuning artifacts.",
    )
    parser.add_argument(
        "--n-iter",
        type=int,
        default=N_ITER,
        help=f"Number of random search trials. Default: {N_ITER}.",
    )
    parser.add_argument(
        "--n-splits",
        type=int,
        default=N_SPLITS,
        help=f"Number of StratifiedGroupKFold folds. Default: {N_SPLITS}.",
    )
    parser.add_argument(
        "--n-jobs",
        type=int,
        default=-1,
        help="Parallel jobs for CV folds. LightGBM itself always uses n_jobs=1.",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=RANDOM_STATE,
        help=f"Random seed. Default: {RANDOM_STATE}.",
    )
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if args.n_iter < 1:
        raise ValueError("--n-iter must be at least 1")
    if args.n_splits < 2:
        raise ValueError("--n-splits must be at least 2")
    if args.n_jobs == 0:
        raise ValueError("--n-jobs cannot be 0")


def ensure_output_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_train_csv(csv_path: Path) -> pd.DataFrame:
    csv_path = csv_path.resolve()
    if not csv_path.is_file():
        raise FileNotFoundError(f"Train CSV not found: {csv_path}")
    if csv_path.suffix.lower() != ".csv":
        raise ValueError(f"Train split path must point to a CSV file: {csv_path}")
    return pd.read_csv(csv_path).reset_index(drop=True)


def validate_train_frame(df: pd.DataFrame, n_splits: int) -> None:
    required_columns = {"gt_class", "group_id"}
    missing = sorted(required_columns - set(df.columns))
    if missing:
        raise ValueError(f"Train CSV is missing required columns: {missing}")

    if df["group_id"].isna().any():
        raise ValueError("Column 'group_id' contains missing values")

    encoded = df["gt_class"].map(vectorize.LABEL_MAP)
    if encoded.isna().any():
        unknown = sorted(df.loc[encoded.isna(), "gt_class"].astype(str).unique().tolist())
        raise ValueError(f"Unknown class labels in 'gt_class': {unknown}")

    num_groups = df["group_id"].nunique()
    if num_groups < n_splits:
        raise ValueError(
            f"StratifiedGroupKFold requires at least {n_splits} groups, got {num_groups}"
        )


def normalize_params(params: Mapping[str, object]) -> Dict[str, object]:
    return {
        "num_leaves": int(params["num_leaves"]),
        "min_child_samples": int(params["min_child_samples"]),
        "subsample": float(params["subsample"]),
        "colsample_bytree": float(params["colsample_bytree"]),
        "max_depth": int(params["max_depth"]),
        "learning_rate": float(params["learning_rate"]),
    }


def build_param_samples(n_iter: int, random_state: int) -> List[Dict[str, object]]:
    sampler = ParameterSampler(
        PARAM_DISTRIBUTIONS,
        n_iter=n_iter,
        random_state=random_state,
    )
    return [normalize_params(params) for params in sampler]


def make_splits(
    df: pd.DataFrame,
    n_splits: int,
    random_state: int,
) -> List[tuple[np.ndarray, np.ndarray]]:
    y = df["gt_class"].map(vectorize.LABEL_MAP).to_numpy(dtype=np.int64)
    groups = df["group_id"].astype(str).to_numpy()
    splitter = StratifiedGroupKFold(
        n_splits=n_splits,
        shuffle=True,
        random_state=random_state,
    )
    return list(splitter.split(df, y, groups))


def parse_is_augmented_mask(df: pd.DataFrame) -> np.ndarray:
    if "is_augmented" not in df.columns:
        return np.zeros(len(df), dtype=bool)

    raw = df["is_augmented"]
    if pd.api.types.is_bool_dtype(raw):
        return raw.fillna(False).to_numpy(dtype=bool)

    normalized = raw.astype(str).str.strip().str.lower()
    true_values = {"true", "1", "yes", "y", "t"}
    return normalized.isin(true_values).to_numpy(dtype=bool)


def compute_augmented_recall(
    valid_df: pd.DataFrame,
    y_true: np.ndarray,
    y_pred: np.ndarray,
) -> Dict[str, float | int]:
    is_augmented_mask = parse_is_augmented_mask(valid_df)
    augmented_ransomware_mask = is_augmented_mask & (y_true == RANSOMWARE_LABEL)
    total = int(np.sum(augmented_ransomware_mask))
    if total == 0:
        return {
            "augmented_recall": float("nan"),
            "num_augmented_ransomware_samples": 0,
        }

    correct = int(np.sum(y_pred[augmented_ransomware_mask] == RANSOMWARE_LABEL))
    return {
        "augmented_recall": float(correct / total),
        "num_augmented_ransomware_samples": total,
    }


def evaluate_fold(
    fold_idx: int,
    train_df: pd.DataFrame,
    valid_df: pd.DataFrame,
    params: Mapping[str, object],
    random_state: int,
) -> Dict[str, float | int]:
    results = vectorize.vectorize(
        train_df=train_df,
        valid_df=valid_df,
        test_df=valid_df,
        persist=False,
    )

    clf = LGBMClassifier(
        n_estimators=LGBM_N_ESTIMATORS,
        class_weight=results["class_weights"],
        random_state=random_state,
        n_jobs=LGBM_N_JOBS,
        subsample_freq=LGBM_SUBSAMPLE_FREQ,
        verbosity=-1,
        **params,
    )

    X_train = results["X_train"]
    y_train = results["y_train"].to_numpy(dtype=np.int64)
    X_valid = results["X_valid"]
    y_valid = results["y_valid"].to_numpy(dtype=np.int64)

    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_valid)

    class_2_f1 = float(
        f1_score(
            y_valid,
            y_pred,
            labels=[RANSOMWARE_LABEL],
            average=None,
            zero_division=0,
        )[0]
    )
    macro_f1 = float(
        f1_score(
            y_valid,
            y_pred,
            labels=LABELS,
            average="macro",
            zero_division=0,
        )
    )
    class_2_recall = float(
        recall_score(
            y_valid,
            y_pred,
            labels=[RANSOMWARE_LABEL],
            average=None,
            zero_division=0,
        )[0]
    )
    augmented_recall = compute_augmented_recall(valid_df, y_valid, y_pred)

    return {
        "fold": int(fold_idx),
        "class_2_f1": class_2_f1,
        "macro_f1": macro_f1,
        "class_2_recall": class_2_recall,
        "augmented_recall": float(augmented_recall["augmented_recall"]),
        "num_augmented_ransomware_samples": int(
            augmented_recall["num_augmented_ransomware_samples"]
        ),
    }


def nan_mean_std(values: np.ndarray) -> tuple[float, float]:
    finite_values = values[np.isfinite(values)]
    if finite_values.size == 0:
        return float("nan"), float("nan")
    return float(finite_values.mean()), float(finite_values.std(ddof=0))


def evaluate_trial(
    trial_idx: int,
    df: pd.DataFrame,
    splits: Iterable[tuple[np.ndarray, np.ndarray]],
    params: Mapping[str, object],
    n_jobs: int,
    random_state: int,
) -> Dict[str, object]:
    started_at = time.perf_counter()
    fold_tasks = []
    for fold_idx, (train_idx, valid_idx) in enumerate(splits, start=1):
        fold_tasks.append(
            (
                fold_idx,
                df.iloc[train_idx].reset_index(drop=True),
                df.iloc[valid_idx].reset_index(drop=True),
            )
        )

    fold_results = Parallel(n_jobs=n_jobs, prefer="threads")(
        delayed(evaluate_fold)(fold_idx, fold_train_df, fold_valid_df, params, random_state)
        for fold_idx, fold_train_df, fold_valid_df in fold_tasks
    )

    class_2_f1_values = np.asarray(
        [result["class_2_f1"] for result in fold_results],
        dtype=np.float64,
    )
    macro_f1_values = np.asarray(
        [result["macro_f1"] for result in fold_results],
        dtype=np.float64,
    )
    class_2_recall_values = np.asarray(
        [result["class_2_recall"] for result in fold_results],
        dtype=np.float64,
    )
    augmented_recall_values = np.asarray(
        [result["augmented_recall"] for result in fold_results],
        dtype=np.float64,
    )
    augmented_recall_mean, augmented_recall_std = nan_mean_std(augmented_recall_values)

    row: Dict[str, object] = {
        "trial": int(trial_idx),
        **params,
        "class_2_f1_mean": float(class_2_f1_values.mean()),
        "class_2_f1_std": float(class_2_f1_values.std(ddof=0)),
        "macro_f1_mean": float(macro_f1_values.mean()),
        "macro_f1_std": float(macro_f1_values.std(ddof=0)),
        "class_2_recall_mean": float(class_2_recall_values.mean()),
        "class_2_recall_std": float(class_2_recall_values.std(ddof=0)),
        "augmented_recall_mean": augmented_recall_mean,
        "augmented_recall_std": augmented_recall_std,
        "augmented_ransomware_samples_total": int(
            sum(result["num_augmented_ransomware_samples"] for result in fold_results)
        ),
        "elapsed_seconds": float(time.perf_counter() - started_at),
    }

    for result in fold_results:
        fold = int(result["fold"])
        row[f"fold_{fold}_class_2_f1"] = float(result["class_2_f1"])
        row[f"fold_{fold}_macro_f1"] = float(result["macro_f1"])
        row[f"fold_{fold}_class_2_recall"] = float(result["class_2_recall"])
        row[f"fold_{fold}_augmented_recall"] = float(result["augmented_recall"])
        row[f"fold_{fold}_augmented_ransomware_samples"] = int(
            result["num_augmented_ransomware_samples"]
        )

    return row


def save_trials_log(trials_df: pd.DataFrame, output_dir: Path) -> Path:
    output_path = output_dir / TRIALS_FILENAME
    trials_df.to_csv(output_path, index=False, encoding="utf-8")
    return output_path


def save_optimization_history(trials_df: pd.DataFrame, output_dir: Path) -> Path:
    output_path = output_dir / HISTORY_PLOT_FILENAME
    history = trials_df["class_2_f1_mean"].cummax()

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.plot(trials_df["trial"], history, marker="o", linewidth=1.8, markersize=3.5)
    ax.set_xlabel("Проба")
    ax.set_ylabel("Среднее значение F1 для целевого класса")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    return output_path


def binned_series(
    series: pd.Series,
    *,
    bins: List[float] | None = None,
    labels: List[str] | None = None,
    value_labels: Mapping[object, str] | None = None,
) -> pd.Series:
    if bins is not None:
        if labels is None:
            raise ValueError("labels must be provided with bins")
        return pd.cut(series, bins=bins, labels=labels, include_lowest=True)

    if value_labels is not None:
        mapped = series.map(value_labels)
        return pd.Categorical(mapped, categories=list(value_labels.values()), ordered=True)

    raise ValueError("Either bins or value_labels must be provided")


def save_pair_heatmap(
    trials_df: pd.DataFrame,
    output_dir: Path,
    filename: str,
    *,
    row_param: str,
    col_param: str,
    row_labels: List[str],
    col_labels: List[str],
    title: str,
    row_bins: List[float] | None = None,
    col_bins: List[float] | None = None,
    row_value_labels: Mapping[object, str] | None = None,
    col_value_labels: Mapping[object, str] | None = None,
) -> Path:
    output_path = output_dir / filename
    working = trials_df.copy()
    working["row_bin"] = binned_series(
        working[row_param],
        bins=row_bins,
        labels=row_labels if row_bins is not None else None,
        value_labels=row_value_labels,
    )
    working["col_bin"] = binned_series(
        working[col_param],
        bins=col_bins,
        labels=col_labels if col_bins is not None else None,
        value_labels=col_value_labels,
    )

    grouped = working.groupby(["row_bin", "col_bin"], observed=False)["class_2_f1_mean"]
    mean_table = grouped.mean().unstack()
    count_table = grouped.count().unstack()
    mean_table = mean_table.reindex(index=row_labels, columns=col_labels)
    count_table = count_table.reindex(index=row_labels, columns=col_labels).fillna(0)

    data = mean_table.to_numpy(dtype=np.float64)
    masked_data = np.ma.masked_invalid(data)
    cmap = plt.cm.viridis.copy()
    cmap.set_bad("#eeeeee")

    fig, ax = plt.subplots(figsize=(9, 6))
    im = ax.imshow(masked_data, cmap=cmap, aspect="auto")
    cbar = fig.colorbar(im, ax=ax)
    cbar.set_label("Среднее значение F1 для целевого класса")

    ax.set_xticks(np.arange(len(col_labels)))
    ax.set_xticklabels(col_labels)
    ax.set_yticks(np.arange(len(row_labels)))
    ax.set_yticklabels(row_labels)
    ax.set_xlabel(col_param)
    ax.set_ylabel(row_param)
    ax.set_title(title)

    for row_idx, _ in enumerate(row_labels):
        for col_idx, _ in enumerate(col_labels):
            count = int(count_table.iloc[row_idx, col_idx])
            value = data[row_idx, col_idx]
            if count == 0 or np.isnan(value):
                text = "n=0"
            else:
                text = f"{value:.3f}\nn={count}"
            ax.text(
                col_idx,
                row_idx,
                text,
                ha="center",
                va="center",
                color="white" if count > 0 else "black",
                fontsize=9,
            )

    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    return output_path


def save_pair_heatmaps(trials_df: pd.DataFrame, output_dir: Path) -> List[Path]:
    learning_rate_labels = {0.01: "0.01", 0.03: "0.03", 0.05: "0.05", 0.1: "0.10"}
    max_depth_labels = {3: "3", 5: "5", 7: "7", 10: "10", -1: "-1\nunlimited"}

    return [
        save_pair_heatmap(
            trials_df,
            output_dir,
            NUM_LEAVES_MIN_CHILD_HEATMAP_FILENAME,
            row_param="num_leaves",
            col_param="min_child_samples",
            row_bins=NUM_LEAVES_BIN_EDGES,
            col_bins=MIN_CHILD_BIN_EDGES,
            row_labels=NUM_LEAVES_BIN_LABELS,
            col_labels=MIN_CHILD_BIN_LABELS,
            title="F1 целевого класса от num_leaves x min_child_samples",
        ),
        save_pair_heatmap(
            trials_df,
            output_dir,
            LEARNING_RATE_NUM_LEAVES_HEATMAP_FILENAME,
            row_param="learning_rate",
            col_param="num_leaves",
            row_value_labels=learning_rate_labels,
            col_bins=NUM_LEAVES_BIN_EDGES,
            row_labels=LEARNING_RATE_LABELS,
            col_labels=NUM_LEAVES_BIN_LABELS,
            title="F1 целевого класса от learning_rate x num_leaves",
        ),
        save_pair_heatmap(
            trials_df,
            output_dir,
            MAX_DEPTH_NUM_LEAVES_HEATMAP_FILENAME,
            row_param="max_depth",
            col_param="num_leaves",
            row_value_labels=max_depth_labels,
            col_bins=NUM_LEAVES_BIN_EDGES,
            row_labels=MAX_DEPTH_LABELS,
            col_labels=NUM_LEAVES_BIN_LABELS,
            title="F1 целевого класса от max_depth x num_leaves",
        ),
        save_pair_heatmap(
            trials_df,
            output_dir,
            SUBSAMPLE_COLSAMPLE_HEATMAP_FILENAME,
            row_param="subsample",
            col_param="colsample_bytree",
            row_bins=SUBSAMPLE_BIN_EDGES,
            col_bins=SUBSAMPLE_BIN_EDGES,
            row_labels=SUBSAMPLE_BIN_LABELS,
            col_labels=SUBSAMPLE_BIN_LABELS,
            title="F1 целевого класса от subsample x colsample_bytree",
        ),
    ]


def save_spearman_heatmap(trials_df: pd.DataFrame, output_dir: Path) -> Path:
    output_path = output_dir / SPEARMAN_HEATMAP_FILENAME
    working = trials_df.copy()
    # max_depth=-1 means "unlimited"; encode it after 10 for rank correlation.
    working["max_depth_corr"] = working["max_depth"].replace({-1: 11})

    corr_columns = [
        "num_leaves",
        "min_child_samples",
        "subsample",
        "colsample_bytree",
        "max_depth_corr",
        "learning_rate",
        "class_2_f1_mean",
        "class_2_recall_mean",
    ]
    corr = working[corr_columns].corr(method="spearman")

    data = corr.to_numpy(dtype=np.float64)
    masked_data = np.ma.masked_invalid(data)
    cmap = plt.cm.coolwarm.copy()
    cmap.set_bad("#eeeeee")

    fig, ax = plt.subplots(figsize=(10, 8))
    im = ax.imshow(masked_data, cmap=cmap, vmin=-1.0, vmax=1.0)
    cbar = fig.colorbar(im, ax=ax)
    cbar.set_label("Корреляция Спирмена")

    ax.set_xticks(np.arange(len(corr_columns)))
    ax.set_xticklabels(corr_columns, rotation=45, ha="right")
    ax.set_yticks(np.arange(len(corr_columns)))
    ax.set_yticklabels(corr_columns)
    ax.set_title("Матрица корреляции Спирмена")

    for row_idx in range(len(corr_columns)):
        for col_idx in range(len(corr_columns)):
            value = data[row_idx, col_idx]
            text = "nan" if np.isnan(value) else f"{value:.2f}"
            ax.text(
                col_idx,
                row_idx,
                text,
                ha="center",
                va="center",
                color="white" if not np.isnan(value) and abs(value) > 0.5 else "black",
                fontsize=8,
            )

    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    return output_path


def save_best_params(trials_df: pd.DataFrame, output_dir: Path, runtime_seconds: float) -> Path:
    output_path = output_dir / "best_random_search_result.json"
    best_idx = int(trials_df["class_2_f1_mean"].idxmax())
    best_row = trials_df.loc[best_idx]
    param_names = list(PARAM_DISTRIBUTIONS.keys())
    payload = {
        "best_trial": int(best_row["trial"]),
        "best_class_2_f1_mean": float(best_row["class_2_f1_mean"]),
        "best_class_2_f1_std": float(best_row["class_2_f1_std"]),
        "best_macro_f1_mean": float(best_row["macro_f1_mean"]),
        "best_macro_f1_std": float(best_row["macro_f1_std"]),
        "best_class_2_recall_mean": float(best_row["class_2_recall_mean"]),
        "best_class_2_recall_std": float(best_row["class_2_recall_std"]),
        "best_augmented_recall_mean": (
            None
            if pd.isna(best_row["augmented_recall_mean"])
            else float(best_row["augmented_recall_mean"])
        ),
        "best_augmented_recall_std": (
            None
            if pd.isna(best_row["augmented_recall_std"])
            else float(best_row["augmented_recall_std"])
        ),
        "best_augmented_ransomware_samples_total": int(
            best_row["augmented_ransomware_samples_total"]
        ),
        "best_params": {
            name: (
                int(best_row[name])
                if name in {"num_leaves", "min_child_samples", "max_depth"}
                else float(best_row[name])
            )
            for name in param_names
        },
        "runtime_seconds": float(runtime_seconds),
    }
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=True, indent=2)
        handle.write("\n")
    return output_path


def main() -> None:
    args = parse_args()
    validate_args(args)
    output_dir = ensure_output_dir(args.odir.resolve())
    train_df = load_train_csv(args.train_csv)
    validate_train_frame(train_df, args.n_splits)

    total_started_at = time.perf_counter()
    splits = make_splits(train_df, args.n_splits, args.random_state)
    param_samples = build_param_samples(args.n_iter, args.random_state)

    rows: List[Dict[str, object]] = []
    best_class_2_f1 = -np.inf
    for trial_idx, params in enumerate(param_samples, start=1):
        row = evaluate_trial(
            trial_idx=trial_idx,
            df=train_df,
            splits=splits,
            params=params,
            n_jobs=args.n_jobs,
            random_state=args.random_state,
        )
        rows.append(row)
        best_class_2_f1 = max(best_class_2_f1, float(row["class_2_f1_mean"]))
        print(
            (
                f"Trial {trial_idx}/{args.n_iter}: "
                f"class_2_f1_mean={row['class_2_f1_mean']:.6f}, "
                f"class_2_recall_mean={row['class_2_recall_mean']:.6f}, "
                f"augmented_recall_mean={row['augmented_recall_mean']:.6f}, "
                f"best_class_2_f1={best_class_2_f1:.6f}"
            ),
            flush=True,
        )

    runtime_seconds = time.perf_counter() - total_started_at
    trials_df = pd.DataFrame(rows)

    trials_path = save_trials_log(trials_df, output_dir)
    history_path = save_optimization_history(trials_df, output_dir)
    heatmap_paths = save_pair_heatmaps(trials_df, output_dir)
    spearman_path = save_spearman_heatmap(trials_df, output_dir)
    best_path = save_best_params(trials_df, output_dir, runtime_seconds)

    print(f"Total runtime: {runtime_seconds:.2f} seconds")
    print(f"Trials log saved to: {trials_path}")
    print(f"Optimization history saved to: {history_path}")
    for heatmap_path in heatmap_paths:
        print(f"Heatmap saved to: {heatmap_path}")
    print(f"Spearman correlation heatmap saved to: {spearman_path}")
    print(f"Best result saved to: {best_path}")


if __name__ == "__main__":
    main()
