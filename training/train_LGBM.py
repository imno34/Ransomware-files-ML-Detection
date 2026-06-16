#train_LGBM.py

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import lightgbm as lgb
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
METRICS_FILENAME = "metrics_test.json"
ROC_PLOT_FILENAME = "roc_curve_lgbm.png"
TEST_PREDICTIONS_FILENAME = "test_predictions.csv"
EARLY_STOPPING_PLOT_FILENAME = "early_stopping_lgbm.png"
EARLY_STOPPING_ROUNDS = 100

# Load split CSV from an explicit path
def load_split(csv_path: Path, split_name: str) -> pd.DataFrame:
    csv_path = csv_path.resolve()
    if not csv_path.is_file():
        raise FileNotFoundError(f"Файл сплита не найден: {csv_path}")
    if csv_path.suffix.lower() != ".csv":
        raise ValueError(f"{split_name} split path must point to a CSV file: {csv_path}")
    return pd.read_csv(csv_path)


# Ensure output directory exists
def ensure_output_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path

# Load and vectorize split CSVs
def vectorize_splits(
    train_split_path: Path,
    valid_split_path: Path,
    test_split_path: Path,
    output_dir: Path,
) -> Dict[str, pd.DataFrame]:
    train_df = load_split(train_split_path, "train")
    valid_df = load_split(valid_split_path, "valid")
    test_df = load_split(test_split_path, "test")

    # Call the main vectorization pipeline from vectorize.py
    return vectorize.vectorize(
        train_df=train_df,
        valid_df=valid_df,
        test_df=test_df,
        output_dir=output_dir,
    )
# Train LightGBM classifier
def train_classifier(
    results: Dict[str, pd.DataFrame],
) -> tuple[LGBMClassifier, Dict[str, Dict[str, list[float]]]]:
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
    X_valid = results["X_valid"]
    y_valid = results["y_valid"].to_numpy(dtype=np.int64)
    evals_result: Dict[str, Dict[str, list[float]]] = {}

    # Fit the model
    clf.fit(
        X_train,
        y_train,
        eval_set=[(X_train, y_train), (X_valid, y_valid)],
        eval_names=["train_A", "valid_B"],
        eval_metric="multi_logloss",
        callbacks=[
            lgb.early_stopping(EARLY_STOPPING_ROUNDS, verbose=False),
            lgb.record_evaluation(evals_result),
        ],
    )
    return clf, evals_result


def save_early_stopping_plot(
    clf: LGBMClassifier,
    evals_result: Dict[str, Dict[str, list[float]]],
    output_dir: Path,
) -> None:
    train_loss = evals_result.get("train_A", {}).get("multi_logloss", [])
    valid_loss = evals_result.get("valid_B", {}).get("multi_logloss", [])
    if not train_loss or not valid_loss:
        raise RuntimeError("LightGBM evaluation history does not contain multi_logloss")

    fig, ax = plt.subplots(figsize=(8, 6))
    train_iterations = np.arange(1, len(train_loss) + 1)
    valid_iterations = np.arange(1, len(valid_loss) + 1)
    ax.plot(train_iterations, train_loss, label="train_A")
    ax.plot(valid_iterations, valid_loss, label="valid_B")

    best_iteration = int(getattr(clf, "best_iteration_", 0) or len(valid_loss))
    ax.axvline(
        best_iteration,
        color="red",
        linestyle="--",
        label=f"Early stopping: {best_iteration}",
    )
    ax.set_xlabel("Boosting iteration")
    ax.set_ylabel("multi_logloss")
    ax.set_title("LightGBM Early Stopping")
    ax.legend(loc="best")
    fig.tight_layout()
    fig.savefig(output_dir / EARLY_STOPPING_PLOT_FILENAME, dpi=150)
    plt.close(fig)


def parse_is_augmented_mask(test_df: pd.DataFrame) -> np.ndarray:
    # Non-strict parsing: treat missing or unknown values as False.
    if "is_augmented" not in test_df.columns:
        return np.zeros(len(test_df), dtype=bool)

    raw = test_df["is_augmented"]
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
    test_df: pd.DataFrame,
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
    missing = sorted(col for col in required_cols if col not in test_df.columns)
    if missing:
        raise ValueError(f"test split must contain columns for PCS: {missing}")

    working = test_df[["pair_id", "aug_parent"]].copy()
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

# Compute test metrics
def compute_metrics(
    clf: LGBMClassifier,
    results: Dict[str, pd.DataFrame],
    test_df: pd.DataFrame,
    output_dir: Path,
) -> Dict[str, object]:
    X_test = results["X_test"]
    y_test = results["y_test"].to_numpy(dtype=np.int64)
    is_augmented_mask = parse_is_augmented_mask(test_df)

    # Generate predictions
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)

    # Compute F1 metrics (macro and per-class)
    macro_f1 = float(f1_score(y_test, y_pred, labels=LABELS, average="macro", zero_division=0))
    per_class_f1 = f1_score(
        y_test,
        y_pred,
        labels=LABELS,
        average=None,
        zero_division=0,
    )
    # Compute confusion matrix
    confusion = confusion_matrix(y_test, y_pred, labels=LABELS).astype(int).tolist()

    # Compute PR-AUC and ROC-AUC for each class
    pr_auc = {}
    roc_auc = {}
    fig, ax = plt.subplots(figsize=(8, 6))
    for idx, label in enumerate(LABELS):
        binary_truth = (y_test == label).astype(int)
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
    ax.set_title("ROC Curve (test)")
    ax.legend(loc="lower right")
    roc_path = output_dir / ROC_PLOT_FILENAME
    fig.tight_layout()
    fig.savefig(roc_path, dpi=150)
    plt.close(fig)

    augmented_recall = compute_augmented_recall(is_augmented_mask, y_test, y_pred)
    pcs = compute_pair_consistency_score(test_df, is_augmented_mask, y_test, y_pred)

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


def save_test_predictions(
    clf: LGBMClassifier,
    results: Dict[str, pd.DataFrame],
    test_df: pd.DataFrame,
    output_dir: Path,
) -> None:
    X_test = results["X_test"]
    y_pred = clf.predict(X_test)
    y_proba_raw = clf.predict_proba(X_test)

    test_predictions_df = test_df.copy()
    test_predictions_df["y_pred"] = y_pred.astype(np.int64)

    # Align probability columns with clf.classes_
    proba_by_label = np.zeros((len(test_predictions_df), len(LABELS)), dtype=np.float64)
    class_to_idx = {int(cls): idx for idx, cls in enumerate(clf.classes_)}
    for label_pos, label in enumerate(LABELS):
        src_idx = class_to_idx.get(int(label))
        if src_idx is not None:
            proba_by_label[:, label_pos] = y_proba_raw[:, src_idx]

    for label_pos, label in enumerate(LABELS):
        test_predictions_df[f"y_proba_{label}"] = proba_by_label[:, label_pos]

    test_predictions_df.to_csv(
        output_dir / TEST_PREDICTIONS_FILENAME,
        index=False,
        encoding="utf-8",
    )

def main() -> None:
    # Parse CLI arguments
    parser = argparse.ArgumentParser(description="Train LightGBM on vectorized dataset splits.")
    parser.add_argument(
        "--trn",
        "--train-split",
        dest="train_split",
        type=Path,
        required=True,
        help="Path to train CSV.",
    )
    parser.add_argument(
        "--vld",
        "--valid-split",
        dest="valid_split",
        type=Path,
        required=True,
        help="Path to valid CSV.",
    )
    parser.add_argument(
        "--tst",
        "--test-split",
        dest="test_split",
        type=Path,
        required=True,
        help="Path to test CSV.",
    )
    parser.add_argument(
        "--odir",
        type=Path,
        required=True,
        help="Directory to store training artifacts (metrics_test.json).",
    )
    args = parser.parse_args()

    output_dir = ensure_output_dir(args.odir.resolve())
    train_split_path = args.train_split.resolve()
    valid_split_path = args.valid_split.resolve()
    test_split_path = args.test_split.resolve()

    # Run training and evaluation
    test_df = load_split(test_split_path, "test")

    results = vectorize_splits(train_split_path, valid_split_path, test_split_path, output_dir)
    clf, evals_result = train_classifier(results)
    save_early_stopping_plot(clf, evals_result, output_dir)
    metrics = compute_metrics(clf, results, test_df, output_dir)
    save_metrics(metrics, output_dir)

    save_test_predictions(clf, results, test_df, output_dir)

    print(f"Обучение завершено. Метрики сохранены в {output_dir / METRICS_FILENAME}")


if __name__ == "__main__":
    main()
