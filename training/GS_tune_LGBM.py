from __future__ import annotations

import argparse
import itertools
import json
import time
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from joblib import Parallel, delayed
from lightgbm import LGBMClassifier, early_stopping, log_evaluation
from sklearn.metrics import f1_score, recall_score
from sklearn.model_selection import StratifiedGroupKFold

import vectorize


LABELS = sorted(vectorize.LABEL_MAP.values())
RANSOMWARE_LABEL = int(vectorize.LABEL_MAP["ransomware-encrypted"])

N_SPLITS = 5
RANDOM_STATE = 42
LGBM_N_ESTIMATORS = 2000
LGBM_N_JOBS = 1
EARLY_STOPPING_ROUNDS = 100

GRID_SEARCH_TRIALS_FILENAME = "grid_search_trials.csv"
BEST_RESULT_FILENAME = "best_grid_search_result.json"
HISTORY_PLOT_FILENAME = "optimization_history_lgbm.png"
LEARNING_RATE_SUBSAMPLE_HEATMAP_FILENAME = "learning_rate_subsample_heatmap.png"
LEARNING_RATE_COLSAMPLE_HEATMAP_FILENAME = "learning_rate_colsample_bytree_heatmap.png"

GRID = {
    "learning_rate": [0.03, 0.05, 0.07, 0.10],
    "subsample": [0.80, 0.90, 1.00],
    "colsample_bytree": [0.70, 0.85, 1.00],
}

FIXED_PARAMS = {
    "num_leaves": 128,
    "min_child_samples": 20,
    "max_depth": -1,
    "subsample_freq": 1,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Grid Search tuning for LightGBM with StratifiedGroupKFold."
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


def build_grid_samples() -> List[Dict[str, object]]:
    keys = list(GRID.keys())
    samples: List[Dict[str, object]] = []
    for values in itertools.product(*(GRID[key] for key in keys)):
        params = {key: value for key, value in zip(keys, values)}
        params.update(FIXED_PARAMS)
        samples.append(
            {
                "num_leaves": int(params["num_leaves"]),
                "min_child_samples": int(params["min_child_samples"]),
                "max_depth": int(params["max_depth"]),
                "learning_rate": float(params["learning_rate"]),
                "subsample": float(params["subsample"]),
                "colsample_bytree": float(params["colsample_bytree"]),
                "subsample_freq": int(params["subsample_freq"]),
            }
        )
    return samples


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
    trial_idx: int,
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
    output_path = output_dir / GRID_SEARCH_TRIALS_FILENAME
    trials_df.to_csv(output_path, index=False, encoding="utf-8")
    return output_path


def save_optimization_history(trials_df: pd.DataFrame, output_dir: Path) -> Path:
    output_path = output_dir / HISTORY_PLOT_FILENAME
    history = trials_df["class_2_f1_mean"].cummax()

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.plot(trials_df["trial"], history, marker="o", linewidth=1.8, markersize=3.5)
    ax.set_xlabel("Trial")
    ax.set_ylabel("Best mean F1 for class 2")
    ax.set_title("Grid Search Optimization History")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    return output_path


def save_exact_pair_heatmap(
    trials_df: pd.DataFrame,
    output_dir: Path,
    filename: str,
    *,
    row_param: str,
    col_param: str,
    row_values: Sequence[int],
    col_values: Sequence[int],
    row_labels: Sequence[str],
    col_labels: Sequence[str],
    title: str,
) -> Path:
    output_path = output_dir / filename
    grouped = trials_df.groupby([row_param, col_param], observed=False)["class_2_f1_mean"]
    mean_table = grouped.mean().unstack()
    count_table = grouped.count().unstack()
    mean_table = mean_table.reindex(index=row_values, columns=col_values)
    count_table = count_table.reindex(index=row_values, columns=col_values).fillna(0)

    data = mean_table.to_numpy(dtype=np.float64)
    masked_data = np.ma.masked_invalid(data)
    cmap = plt.cm.viridis.copy()
    cmap.set_bad("#eeeeee")

    fig, ax = plt.subplots(figsize=(9, 6))
    im = ax.imshow(masked_data, cmap=cmap, aspect="auto")
    cbar = fig.colorbar(im, ax=ax)
    cbar.set_label("Mean F1 for class 2")

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


def save_heatmaps(trials_df: pd.DataFrame, output_dir: Path) -> List[Path]:
    learning_rate_values = GRID["learning_rate"]
    subsample_values = GRID["subsample"]
    colsample_values = GRID["colsample_bytree"]

    return [
        save_exact_pair_heatmap(
            trials_df,
            output_dir,
            LEARNING_RATE_SUBSAMPLE_HEATMAP_FILENAME,
            row_param="learning_rate",
            col_param="subsample",
            row_values=learning_rate_values,
            col_values=subsample_values,
            row_labels=[f"{value:.2f}" for value in learning_rate_values],
            col_labels=[f"{value:.2f}" for value in subsample_values],
            title="Class 2 F1 by learning_rate x subsample",
        ),
        save_exact_pair_heatmap(
            trials_df,
            output_dir,
            LEARNING_RATE_COLSAMPLE_HEATMAP_FILENAME,
            row_param="learning_rate",
            col_param="colsample_bytree",
            row_values=learning_rate_values,
            col_values=colsample_values,
            row_labels=[f"{value:.2f}" for value in learning_rate_values],
            col_labels=[f"{value:.2f}" for value in colsample_values],
            title="Class 2 F1 by learning_rate x colsample_bytree",
        ),
    ]


def save_best_params(
    trials_df: pd.DataFrame,
    output_dir: Path,
    runtime_seconds: float,
    random_state: int,
    early_stopping_rounds: int,
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
        "mean_best_iteration": float(best_row["mean_best_iteration"]),
        "max_best_iteration": int(best_row["max_best_iteration"]),
        "best_params": {
            "learning_rate": float(best_row["learning_rate"]),
            "subsample": float(best_row["subsample"]),
            "colsample_bytree": float(best_row["colsample_bytree"]),
        },
        "fixed_params": {
            "num_leaves": int(FIXED_PARAMS["num_leaves"]),
            "min_child_samples": int(FIXED_PARAMS["min_child_samples"]),
            "max_depth": int(FIXED_PARAMS["max_depth"]),
            "subsample_freq": int(FIXED_PARAMS["subsample_freq"]),
            "n_estimators": int(LGBM_N_ESTIMATORS),
            "random_state": int(random_state),
            "n_jobs": int(LGBM_N_JOBS),
            "early_stopping_rounds": int(early_stopping_rounds),
            "eval_metric": "multi_logloss",
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
    grid_samples = build_grid_samples()

    rows: List[Dict[str, object]] = []
    best_class_2_f1 = -np.inf
    for trial_idx, params in enumerate(grid_samples, start=1):
        row = evaluate_trial(
            trial_idx=trial_idx,
            df=train_df,
            splits=splits,
            params=params,
            n_jobs=args.n_jobs,
            random_state=args.random_state,
            early_stopping_rounds=args.early_stopping_rounds,
        )
        rows.append(row)
        best_class_2_f1 = max(best_class_2_f1, float(row["class_2_f1_mean"]))
        print(
            (
                f"Trial {trial_idx}/{len(grid_samples)}: "
                f"class_2_f1_mean={row['class_2_f1_mean']:.6f}, "
                f"class_2_recall_mean={row['class_2_recall_mean']:.6f}, "
                f"mean_best_iteration={row['mean_best_iteration']:.2f}, "
                f"best_class_2_f1={best_class_2_f1:.6f}"
            ),
            flush=True,
        )

    runtime_seconds = time.perf_counter() - total_started_at
    trials_df = pd.DataFrame(rows)

    trials_path = save_trials_log(trials_df, output_dir)
    history_path = save_optimization_history(trials_df, output_dir)
    heatmap_paths = save_heatmaps(trials_df, output_dir)
    best_path = save_best_params(
        trials_df,
        output_dir,
        runtime_seconds,
        args.random_state,
        args.early_stopping_rounds,
    )

    print(f"Total runtime: {runtime_seconds:.2f} seconds")
    print(f"Trials log saved to: {trials_path}")
    print(f"Optimization history saved to: {history_path}")
    for heatmap_path in heatmap_paths:
        print(f"Heatmap saved to: {heatmap_path}")
    print(f"Best result saved to: {best_path}")


if __name__ == "__main__":
    main()
