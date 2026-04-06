#train_LGBM.py

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    roc_auc_score,
    roc_curve,
)

import vectorize

# Class labels derived from vectorization metadata
LABELS = sorted(vectorize.LABEL_MAP.values())
# Output artifact filenames
METRICS_FILENAME = "metrics_valid.json"
ROC_PLOT_FILENAME = "roc_curve_lgbm.png"
VALID_PREDICTIONS_FILENAME = "valid_predictions.csv"

# Load split CSV (train/valid/test)
def load_split(splits_dir: Path, split_name: str) -> pd.DataFrame:
    csv_path = splits_dir / f"{split_name}.csv"
    if not csv_path.is_file():
        raise FileNotFoundError(f"Файл сплита не найден: {csv_path}")
    return pd.read_csv(csv_path)


def load_train_split(splits_dir: Path, train_split_path: Path | None) -> pd.DataFrame:
    if train_split_path is None:
        return load_split(splits_dir, "train")

    resolved_path = train_split_path.resolve()
    if resolved_path.suffix.lower() != ".csv":
        raise ValueError(f"Train split path must point to a CSV file: {resolved_path}")
    if not resolved_path.is_file():
        raise FileNotFoundError(f"Train split file not found: {resolved_path}")
    return pd.read_csv(resolved_path)


def load_valid_split(splits_dir: Path, valid_split_path: Path | None) -> pd.DataFrame:
    if valid_split_path is None:
        return load_split(splits_dir, "valid")

    resolved_path = valid_split_path.resolve()
    if resolved_path.suffix.lower() != ".csv":
        raise ValueError(f"Valid split path must point to a CSV file: {resolved_path}")
    if not resolved_path.is_file():
        raise FileNotFoundError(f"Valid split file not found: {resolved_path}")
    return pd.read_csv(resolved_path)

# Ensure output directory exists
def ensure_output_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path

# Ensure vectorized subdirectory exists under splits directory
def ensure_vectorized_dir(splits_dir: Path) -> Path:
    path = splits_dir / vectorize.VECTORIZE_SUBDIR
    path.mkdir(parents=True, exist_ok=True)
    return path

# Load and vectorize split CSVs
def vectorize_splits(
    splits_dir: Path,
    train_split_path: Path | None = None,
    valid_split_path: Path | None = None,
) -> Dict[str, pd.DataFrame]:
    train_df = load_train_split(splits_dir, train_split_path)
    valid_df = load_valid_split(splits_dir, valid_split_path)
    test_df = load_split(splits_dir, "test")

    # Call the main vectorization pipeline from vectorize.py
    return vectorize.vectorize(
        train_df=train_df,
        valid_df=valid_df,
        test_df=test_df,
        splits_dir=splits_dir,
    )
# Train LightGBM classifier
def train_classifier(results: Dict[str, pd.DataFrame]) -> LGBMClassifier:
    clf = LGBMClassifier(
        num_leaves=64,
        n_estimators=700,
        learning_rate=0.05,
        max_depth=-1,
        subsample=0.9,
        colsample_bytree=0.9,
        class_weight=results["class_weights"],  # Class weights computed during vectorization
        random_state=42,
    )
    X_train = results["X_train"]
    y_train = results["y_train"].to_numpy(dtype=np.int64)
    
    # Fit the model
    clf.fit(X_train, y_train)
    return clf


def parse_is_augmented_mask(valid_df: pd.DataFrame) -> np.ndarray:
    # Non-strict parsing: treat missing or unknown values as False.
    if "is_augmented" not in valid_df.columns:
        return np.zeros(len(valid_df), dtype=bool)

    raw = valid_df["is_augmented"]
    if pd.api.types.is_bool_dtype(raw):
        return raw.fillna(False).to_numpy(dtype=bool)

    normalized = raw.astype(str).str.strip().str.lower()
    true_values = {"true", "1", "yes", "y", "t"}
    return normalized.isin(true_values).to_numpy(dtype=bool)


def compute_augmented_recall(
    is_augmented_mask: np.ndarray,
    y_true: np.ndarray,
    y_pred: np.ndarray,
) -> Dict[str, object]:
    ransomware_label = int(vectorize.LABEL_MAP["ransomware-encrypted"])
    ransomware_aug_mask = (
        is_augmented_mask &
        (y_true == ransomware_label)
    )
    total = int(np.sum(ransomware_aug_mask))
    if total == 0:
        return {
            "ransomware_encrypted_recall": None,
            "num_augmented_ransomware_samples": 0,
        }

    correct = int(np.sum(y_pred[ransomware_aug_mask] == ransomware_label))
    recall_value = float(correct / total)
    return {
        "ransomware_encrypted_recall": recall_value,
        "num_augmented_ransomware_samples": total,
    }


def compute_pair_consistency_score(
    valid_df: pd.DataFrame,
    is_augmented_mask: np.ndarray,
    y_true: np.ndarray,
    y_pred: np.ndarray,
) -> Dict[str, object]:
    ransomware_label = int(vectorize.LABEL_MAP["ransomware-encrypted"])
    source_labels = {
        int(vectorize.LABEL_MAP["benign"]),
        int(vectorize.LABEL_MAP["benign-encrypted"]),
    }

    required_cols = {"pair_id", "aug_parent"}
    missing = sorted(col for col in required_cols if col not in valid_df.columns)
    if missing:
        raise ValueError(f"valid split must contain columns for PCS: {missing}")

    working = valid_df[["pair_id", "aug_parent"]].copy()
    working["is_augmented"] = is_augmented_mask
    working["y_true"] = y_true.astype(np.int64)
    working["y_pred"] = y_pred.astype(np.int64)

    augmented_ransomware = working.loc[
        (working["is_augmented"]) & (working["y_true"] == ransomware_label),
        ["pair_id", "aug_parent", "y_pred"],
    ].rename(columns={"y_pred": "aug_pred"})
    if augmented_ransomware.empty:
        return {
            "value": None,
            "num_augmented_ransomware_samples": 0,
            "num_samples_used": 0,
        }

    if augmented_ransomware["aug_parent"].isna().any():
        raise ValueError("Found augmented ransomware rows with null 'aug_parent'")
    augmented_ransomware["aug_parent"] = augmented_ransomware["aug_parent"].astype(str).str.strip()
    if augmented_ransomware["aug_parent"].eq("").any():
        raise ValueError("Found augmented ransomware rows with empty 'aug_parent'")

    baseline_sources = working.loc[
        (~working["is_augmented"]) & (working["y_true"].isin(source_labels)),
        ["pair_id", "y_true", "y_pred"],
    ].rename(columns={"y_true": "source_true", "y_pred": "source_pred"})

    candidate_pair_ids = set(augmented_ransomware["aug_parent"].tolist())
    duplicates = baseline_sources.loc[
        baseline_sources["pair_id"].isin(candidate_pair_ids), "pair_id"
    ]
    dup_counts = duplicates.value_counts()
    dup_pair_ids = dup_counts[dup_counts > 1].index.tolist()
    if dup_pair_ids:
        raise ValueError(
            f"Multiple baseline source rows for pair_id(s): {dup_pair_ids[:10]}"
        )

    joined = augmented_ransomware.merge(
        baseline_sources,
        left_on="aug_parent",
        right_on="pair_id",
        how="left",
    )
    if joined["source_pred"].isna().any():
        missing_parents = sorted(set(joined.loc[joined["source_pred"].isna(), "aug_parent"].tolist()))
        raise ValueError(f"Missing baseline source rows for aug_parent(s): {missing_parents[:10]}")

    aug_is_ransomware = joined["aug_pred"] == ransomware_label
    source_is_correct = joined["source_pred"] == joined["source_true"]
    success_mask = aug_is_ransomware & source_is_correct
    pcs_value = float(success_mask.mean())
    return {
        "value": pcs_value,
        "num_augmented_ransomware_samples": int(augmented_ransomware.shape[0]),
        "num_samples_used": int(joined.shape[0]),
    }

# Compute validation metrics
def compute_metrics(
    clf: LGBMClassifier,
    results: Dict[str, pd.DataFrame],
    valid_df: pd.DataFrame,
    output_dir: Path,
) -> Dict[str, object]:
    X_valid = results["X_valid"]
    y_valid = results["y_valid"].to_numpy(dtype=np.int64)
    is_augmented_mask = parse_is_augmented_mask(valid_df)

    # Generate predictions
    y_pred = clf.predict(X_valid)
    y_proba = clf.predict_proba(X_valid)

    # Compute F1 metrics (macro and per-class)
    macro_f1 = float(f1_score(y_valid, y_pred, labels=LABELS, average="macro", zero_division=0))
    per_class_f1 = f1_score(
        y_valid,
        y_pred,
        labels=LABELS,
        average=None,
        zero_division=0,
    )
    # Compute confusion matrix
    confusion = confusion_matrix(y_valid, y_pred, labels=LABELS).astype(int).tolist()

    # Compute PR-AUC and ROC-AUC for each class
    pr_auc = {}
    roc_auc = {}
    fig, ax = plt.subplots(figsize=(8, 6))
    for idx, label in enumerate(LABELS):
        binary_truth = (y_valid == label).astype(int)
        probs = y_proba[:, idx]
        pr_auc[str(label)] = float(average_precision_score(binary_truth, probs))
        roc_auc[str(label)] = float(roc_auc_score(binary_truth, probs))
        # Build ROC curve
        fpr, tpr, _ = roc_curve(binary_truth, probs)
        ax.plot(fpr, tpr, label=f"Class {label} (AUC={roc_auc[str(label)]:.3f})")

    # Style and save ROC plot
    ax.plot([0, 1], [0, 1], "k--", label="Random chance")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve (validation)")
    ax.legend(loc="lower right")
    roc_path = output_dir / ROC_PLOT_FILENAME
    fig.tight_layout()
    fig.savefig(roc_path, dpi=150)
    plt.close(fig)

    augmented_recall = compute_augmented_recall(is_augmented_mask, y_valid, y_pred)
    pcs = compute_pair_consistency_score(valid_df, is_augmented_mask, y_valid, y_pred)

    # Return metrics payload
    return {
        "macro_f1": macro_f1,
        "per_class_f1": {str(label): float(score) for label, score in zip(LABELS, per_class_f1)},
        "confusion_matrix": confusion,
        "pr_auc": pr_auc,
        "roc_auc": roc_auc,
        "augmented_recall": augmented_recall,
        "pair_consistency_score": pcs,
    }

# Save metrics to JSON
def save_metrics(metrics: Dict[str, object], output_dir: Path) -> None:
    metrics_path = output_dir / METRICS_FILENAME
    with metrics_path.open("w", encoding="utf-8") as fh:
        json.dump(metrics, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def save_valid_predictions(
    clf: LGBMClassifier,
    results: Dict[str, pd.DataFrame],
    valid_df: pd.DataFrame,
    output_dir: Path,
) -> None:
    X_valid = results["X_valid"]
    y_pred = clf.predict(X_valid)
    y_proba_raw = clf.predict_proba(X_valid)

    valid_predictions_df = valid_df.copy()
    valid_predictions_df["y_pred"] = y_pred.astype(np.int64)

    # Align probability columns with class labels 0/1/2 based on clf.classes_
    proba_by_label = np.zeros((len(valid_predictions_df), len(LABELS)), dtype=np.float64)
    class_to_idx = {int(cls): idx for idx, cls in enumerate(clf.classes_)}
    for label_pos, label in enumerate(LABELS):
        src_idx = class_to_idx.get(int(label))
        if src_idx is not None:
            proba_by_label[:, label_pos] = y_proba_raw[:, src_idx]

    for label_pos, label in enumerate(LABELS):
        valid_predictions_df[f"y_proba_{label}"] = proba_by_label[:, label_pos]

    valid_predictions_df.to_csv(
        output_dir / VALID_PREDICTIONS_FILENAME,
        index=False,
        encoding="utf-8",
    )

def main() -> None:
    # Parse CLI arguments
    parser = argparse.ArgumentParser(description="Train LightGBM on vectorized dataset splits.")
    parser.add_argument(
        "--sdir",
        type=Path,
        required=True,
        help="Directory containing train/valid/test CSVs. vectorized/ will be created automatically.",
    )
    parser.add_argument(
        "--odir",
        type=Path,
        required=True,
        help="Directory to store training artifacts (metrics_valid.json).",
    )
    parser.add_argument(
        "--train-split",
        "--trn",
        dest="train_split",
        type=Path,
        default=None,
        help="Optional path to external train CSV. If omitted, splits_dir/train.csv is used.",
    )
    parser.add_argument(
        "--valid-split",
        "--vld",
        dest="valid_split",
        type=Path,
        default=None,
        help="Optional path to external valid CSV. If omitted, splits_dir/valid.csv is used.",
    )
    args = parser.parse_args()

    splits_dir = args.sdir.resolve()
    output_dir = ensure_output_dir(args.odir.resolve())
    train_split_path = args.train_split
    valid_split_path = args.valid_split

    if not splits_dir.is_dir():
        raise FileNotFoundError(f"Директория сплитов не найдена: {splits_dir}")

    ensure_vectorized_dir(splits_dir)

    # Run training and evaluation
    valid_df = load_valid_split(splits_dir, valid_split_path)

    results = vectorize_splits(splits_dir, train_split_path, valid_split_path)
    clf = train_classifier(results)
    metrics = compute_metrics(clf, results, valid_df, output_dir)
    save_metrics(metrics, output_dir)

    save_valid_predictions(clf, results, valid_df, output_dir)

    print(f"Обучение завершено. Метрики сохранены в {output_dir / METRICS_FILENAME}")


if __name__ == "__main__":
    main()
