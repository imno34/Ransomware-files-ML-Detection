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
    recall_score,
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


# Compute test metrics
def compute_metrics(
    clf: LGBMClassifier,
    results: Dict[str, pd.DataFrame],
    output_dir: Path,
) -> Dict[str, object]:
    X_test = results["X_test"]
    y_test = results["y_test"].to_numpy(dtype=np.int64)

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
    ransomware_label = int(vectorize.LABEL_MAP["ransomware-encrypted"])
    ransomware_recall = float(
        recall_score(
            y_test,
            y_pred,
            labels=[ransomware_label],
            average=None,
            zero_division=0,
        )[0]
    )

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

    # Return metrics payload
    return {
        "macro_f1": macro_f1,
        "per_class_f1": {str(label): float(score) for label, score in zip(LABELS, per_class_f1)},
        "confusion_matrix": confusion,
        "pr_auc": pr_auc,
        "roc_auc": roc_auc,
        "class_2_recall": ransomware_recall,
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
    clf = train_classifier(results)
    metrics = compute_metrics(clf, results, output_dir)
    save_metrics(metrics, output_dir)

    save_test_predictions(clf, results, test_df, output_dir)

    print(f"Обучение завершено. Метрики сохранены в {output_dir / METRICS_FILENAME}")


if __name__ == "__main__":
    main()
