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
import optuna
from joblib import Parallel, delayed
from lightgbm import LGBMClassifier, early_stopping, log_evaluation
from sklearn.metrics import f1_score, recall_score
from sklearn.model_selection import StratifiedGroupKFold
from optuna.samplers import TPESampler

import vectorize


LABELS = sorted(vectorize.LABEL_MAP.values())
RANSOMWARE_LABEL = int(vectorize.LABEL_MAP["ransomware-encrypted"])

N_ITER = 150
N_INITIAL_RANDOM_TRIALS = 15
N_SPLITS = 5
RANDOM_STATE = 42
LGBM_N_ESTIMATORS = 2500
LGBM_N_JOBS = 1
EARLY_STOPPING_ROUNDS = 100

BAYESIAN_TRIALS_FILENAME = "bayesian_search_trials.csv"
BEST_RESULT_FILENAME = "best_bayesian_search_result.json"
HISTORY_PLOT_FILENAME = "optimization_history_lgbm.png"
NUM_LEAVES_MIN_CHILD_HEATMAP_FILENAME = "num_leaves_min_child_samples_heatmap.png"
REG_LAMBDA_REG_ALPHA_HEATMAP_FILENAME = "reg_lambda_reg_alpha_heatmap.png"
SUBSAMPLE_COLSAMPLE_HEATMAP_FILENAME = "subsample_colsample_bytree_heatmap.png"
SPEARMAN_HEATMAP_FILENAME = "spearman_correlation_heatmap.png"

NUM_LEAVES_BIN_EDGES = [15, 32, 64, 128, 192]
NUM_LEAVES_BIN_LABELS = [
    "16-32",
    "33-64",
    "65-128",
    "129-192",
]

MIN_CHILD_BIN_EDGES = [9, 30, 60, 100, 160]
MIN_CHILD_BIN_LABELS = [
    "10-30",
    "31-60",
    "61-100",
    "101-160",
]

REG_ALPHA_BIN_EDGES = [1e-8, 1e-4, 1e-2, 1.0, 5.0]
REG_ALPHA_BIN_LABELS = [
    "1e-8-1e-4",
    "1e-4-1e-2",
    "1e-2-1",
    "1-5",
]

REG_LAMBDA_BIN_EDGES = [1e-8, 1e-4, 1e-2, 1.0, 10.0]
REG_LAMBDA_BIN_LABELS = [
    "1e-8-1e-4",
    "1e-4-1e-2",
    "1e-2-1",
    "1-10",
]

SUBSAMPLE_BIN_EDGES = [0.65, 0.75, 0.85, 0.95, 1.0]
SUBSAMPLE_BIN_LABELS = [
    "0.65-0.75",
    "0.75-0.85",
    "0.85-0.95",
    "0.95-1.00",
]

PARAM_NAMES = [
    "num_leaves",
    "min_child_samples",
    "max_depth",
    "learning_rate",
    "subsample",
    "subsample_freq",
    "colsample_bytree",
    "reg_alpha",
    "reg_lambda",
    "min_split_gain",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bayesian Optimization tuning for LightGBM with StratifiedGroupKFold."
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
        help=f"Number of Optuna trials. Default: {N_ITER}.",
    )
    parser.add_argument(
        "--initial-random-trials",
        type=int,
        default=N_INITIAL_RANDOM_TRIALS,
        help=f"Number of initial random Optuna trials. Default: {N_INITIAL_RANDOM_TRIALS}.",
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
    parser.add_argument(
        "--early-stopping-rounds",
        type=int,
        default=EARLY_STOPPING_ROUNDS,
        help=f"Early stopping rounds. Default: {EARLY_STOPPING_ROUNDS}.",
    )
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> None:
    if args.n_iter < 1:
        raise ValueError("--n-iter must be at least 1")
    if args.initial_random_trials < 0:
        raise ValueError("--initial-random-trials cannot be negative")
    if args.initial_random_trials > args.n_iter:
        raise ValueError("--initial-random-trials cannot exceed --n-iter")
    if args.n_splits < 2:
        raise ValueError("--n-splits must be at least 2")
    if args.n_jobs == 0:
        raise ValueError("--n-jobs cannot be 0")
    if args.early_stopping_rounds < 1:
        raise ValueError("--early-stopping-rounds must be at least 1")


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


def suggest_params(trial: optuna.Trial) -> Dict[str, object]:
    return {
        "num_leaves": trial.suggest_int("num_leaves", 16, 192),
        "min_child_samples": trial.suggest_int("min_child_samples", 10, 160),
        "max_depth": trial.suggest_categorical(
            "max_depth",
            [-1, 3, 4, 5, 6, 7, 8, 10, 12],
        ),
        "learning_rate": trial.suggest_float("learning_rate", 0.005, 0.12, log=True),
        "subsample": trial.suggest_float("subsample", 0.65, 1.0),
        "subsample_freq": trial.suggest_int("subsample_freq", 1, 7),
        "colsample_bytree": trial.suggest_float("colsample_bytree", 0.65, 1.0),
        "reg_alpha": trial.suggest_float("reg_alpha", 1e-8, 5.0, log=True),
        "reg_lambda": trial.suggest_float("reg_lambda", 1e-8, 10.0, log=True),
        "min_split_gain": trial.suggest_float("min_split_gain", 0.0, 0.5),
    }


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
    early_stopping_rounds: int,
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
        verbosity=-1,
        **params,
    )

    X_train = results["X_train"]
    y_train = results["y_train"].to_numpy(dtype=np.int64)
    X_valid = results["X_valid"]
    y_valid = results["y_valid"].to_numpy(dtype=np.int64)

    clf.fit(
        X_train,
        y_train,
        eval_set=[(X_valid, y_valid)],
        eval_metric="multi_logloss",
        callbacks=[
            early_stopping(early_stopping_rounds, verbose=False),
            log_evaluation(period=0),
        ],
    )
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
    best_iteration = getattr(clf, "best_iteration_", None)
    if best_iteration is None or best_iteration <= 0:
        best_iteration = LGBM_N_ESTIMATORS

    return {
        "fold": int(fold_idx),
        "class_2_f1": class_2_f1,
        "macro_f1": macro_f1,
        "class_2_recall": class_2_recall,
        "augmented_recall": float(augmented_recall["augmented_recall"]),
        "num_augmented_ransomware_samples": int(
            augmented_recall["num_augmented_ransomware_samples"]
        ),
        "best_iteration": int(best_iteration),
    }


def nan_mean_std(values: np.ndarray) -> tuple[float, float]:
    finite_values = values[np.isfinite(values)]
    if finite_values.size == 0:
        return float("nan"), float("nan")
    return float(finite_values.mean()), float(finite_values.std(ddof=0))


def evaluate_trial(
    trial_number: int,
    df: pd.DataFrame,
    splits: Iterable[tuple[np.ndarray, np.ndarray]],
    params: Mapping[str, object],
    n_jobs: int,
    random_state: int,
    early_stopping_rounds: int,
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
        delayed(evaluate_fold)(
            fold_idx,
            fold_train_df,
            fold_valid_df,
            params,
            random_state,
            early_stopping_rounds,
        )
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
    best_iteration_values = np.asarray(
        [result["best_iteration"] for result in fold_results],
        dtype=np.int64,
    )
    augmented_recall_mean, augmented_recall_std = nan_mean_std(augmented_recall_values)

    row: Dict[str, object] = {
        "trial": int(trial_number + 1),
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
        "mean_best_iteration": float(best_iteration_values.mean()),
        "max_best_iteration": int(best_iteration_values.max()),
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
        row[f"fold_{fold}_best_iteration"] = int(result["best_iteration"])

    return row


def save_trials_log(trials_df: pd.DataFrame, output_dir: Path) -> Path:
    output_path = output_dir / BAYESIAN_TRIALS_FILENAME
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


def binned_series(series: pd.Series, bins: List[float], labels: List[str]) -> pd.Series:
    return pd.cut(series, bins=bins, labels=labels, include_lowest=True)


def save_pair_heatmap(
    trials_df: pd.DataFrame,
    output_dir: Path,
    filename: str,
    *,
    row_param: str,
    col_param: str,
    row_bins: List[float],
    col_bins: List[float],
    row_labels: List[str],
    col_labels: List[str],
    title: str,
) -> Path:
    output_path = output_dir / filename
    working = trials_df.copy()
    working["row_bin"] = binned_series(working[row_param], row_bins, row_labels)
    working["col_bin"] = binned_series(working[col_param], col_bins, col_labels)

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
            REG_LAMBDA_REG_ALPHA_HEATMAP_FILENAME,
            row_param="reg_lambda",
            col_param="reg_alpha",
            row_bins=REG_LAMBDA_BIN_EDGES,
            col_bins=REG_ALPHA_BIN_EDGES,
            row_labels=REG_LAMBDA_BIN_LABELS,
            col_labels=REG_ALPHA_BIN_LABELS,
            title="F1 целевого класса от reg_lambda x reg_alpha",
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
    # max_depth=-1 means "unlimited"; encode it after 12 for rank correlation.
    working["max_depth_corr"] = working["max_depth"].replace({-1: 13})

    corr_columns = [
        "num_leaves",
        "min_child_samples",
        "max_depth_corr",
        "learning_rate",
        "subsample",
        "subsample_freq",
        "colsample_bytree",
        "reg_alpha",
        "reg_lambda",
        "min_split_gain",
        "class_2_f1_mean",
        "class_2_recall_mean",
    ]
    corr = working[corr_columns].corr(method="spearman")

    data = corr.to_numpy(dtype=np.float64)
    masked_data = np.ma.masked_invalid(data)
    cmap = plt.cm.coolwarm.copy()
    cmap.set_bad("#eeeeee")

    fig, ax = plt.subplots(figsize=(12, 10))
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
                fontsize=7,
            )

    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    return output_path


def json_float_or_none(value: object) -> float | None:
    if pd.isna(value):
        return None
    return float(value)


def save_best_params(
    trials_df: pd.DataFrame,
    output_dir: Path,
    runtime_seconds: float,
    random_state: int,
    early_stopping_rounds: int,
    n_initial_random_trials: int,
) -> Path:
    output_path = output_dir / BEST_RESULT_FILENAME
    best_idx = int(trials_df["class_2_f1_mean"].idxmax())
    best_row = trials_df.loc[best_idx]
    payload = {
        "best_trial": int(best_row["trial"]),
        "best_class_2_f1_mean": float(best_row["class_2_f1_mean"]),
        "best_class_2_f1_std": float(best_row["class_2_f1_std"]),
        "best_macro_f1_mean": float(best_row["macro_f1_mean"]),
        "best_macro_f1_std": float(best_row["macro_f1_std"]),
        "best_class_2_recall_mean": float(best_row["class_2_recall_mean"]),
        "best_class_2_recall_std": float(best_row["class_2_recall_std"]),
        "best_augmented_recall_mean": json_float_or_none(
            best_row["augmented_recall_mean"]
        ),
        "best_augmented_recall_std": json_float_or_none(
            best_row["augmented_recall_std"]
        ),
        "best_augmented_ransomware_samples_total": int(
            best_row["augmented_ransomware_samples_total"]
        ),
        "mean_best_iteration": float(best_row["mean_best_iteration"]),
        "max_best_iteration": int(best_row["max_best_iteration"]),
        "best_params": {
            name: (
                int(best_row[name])
                if name in {
                    "num_leaves",
                    "min_child_samples",
                    "max_depth",
                    "subsample_freq",
                }
                else float(best_row[name])
            )
            for name in PARAM_NAMES
        },
        "fixed_params": {
            "n_estimators": int(LGBM_N_ESTIMATORS),
            "random_state": int(random_state),
            "n_jobs": int(LGBM_N_JOBS),
            "early_stopping_rounds": int(early_stopping_rounds),
            "eval_metric": "multi_logloss",
        },
        "optuna": {
            "sampler": "TPESampler",
            "n_initial_random_trials": int(n_initial_random_trials),
            "direction": "maximize",
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
    rows: List[Dict[str, object]] = []

    sampler = TPESampler(
        seed=args.random_state,
        n_startup_trials=args.initial_random_trials,
    )
    optuna.logging.set_verbosity(optuna.logging.WARNING)
    study = optuna.create_study(direction="maximize", sampler=sampler)

    def objective(trial: optuna.Trial) -> float:
        params = suggest_params(trial)
        row = evaluate_trial(
            trial_number=trial.number,
            df=train_df,
            splits=splits,
            params=params,
            n_jobs=args.n_jobs,
            random_state=args.random_state,
            early_stopping_rounds=args.early_stopping_rounds,
        )
        rows.append(row)
        trial.set_user_attr("trial_row", row)
        score = float(row["class_2_f1_mean"])
        best_score = max(float(item["class_2_f1_mean"]) for item in rows)
        print(
            (
                f"Trial {row['trial']}/{args.n_iter}: "
                f"class_2_f1_mean={score:.6f}, "
                f"class_2_recall_mean={row['class_2_recall_mean']:.6f}, "
                f"mean_best_iteration={row['mean_best_iteration']:.2f}, "
                f"best_class_2_f1={best_score:.6f}"
            ),
            flush=True,
        )
        return score

    study.optimize(objective, n_trials=args.n_iter, n_jobs=1, show_progress_bar=False)

    runtime_seconds = time.perf_counter() - total_started_at
    trials_df = pd.DataFrame(rows).sort_values("trial").reset_index(drop=True)

    trials_path = save_trials_log(trials_df, output_dir)
    history_path = save_optimization_history(trials_df, output_dir)
    heatmap_paths = save_pair_heatmaps(trials_df, output_dir)
    spearman_path = save_spearman_heatmap(trials_df, output_dir)
    best_path = save_best_params(
        trials_df,
        output_dir,
        runtime_seconds,
        args.random_state,
        args.early_stopping_rounds,
        args.initial_random_trials,
    )

    print(f"Total runtime: {runtime_seconds:.2f} seconds")
    print(f"Trials log saved to: {trials_path}")
    print(f"Optimization history saved to: {history_path}")
    for heatmap_path in heatmap_paths:
        print(f"Heatmap saved to: {heatmap_path}")
    print(f"Spearman correlation heatmap saved to: {spearman_path}")
    print(f"Best result saved to: {best_path}")


if __name__ == "__main__":
    main()
