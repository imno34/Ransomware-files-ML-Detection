#train_RNC.py

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

import vectorize

RANDOM_SEED = 20240101
# Определение меток классов на основе артефакта после векторизации
LABELS = sorted(vectorize.LABEL_MAP.values())
# Имена файлов для сохранения результатов
METRICS_FILENAME = "metrics_test.json"
ROC_PLOT_FILENAME = "roc_curve_rf.png"
TEST_PREDICTIONS_FILENAME = "test_predictions.csv"

# Загрузка CSV-файла сплита (train/valid/test)
def load_split(splits_dir: Path, split_name: str) -> pd.DataFrame:
    csv_path = splits_dir / f"{split_name}.csv"
    if not csv_path.is_file():
        raise FileNotFoundError(f"Split file not found: {csv_path}")
    return pd.read_csv(csv_path)

# Гарантия существования выходной директории
def ensure_output_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path

# Гарантия существования директории vectorized внутри каталога со сплитами
def ensure_vectorized_dir(splits_dir: Path) -> Path:
    path = splits_dir / vectorize.VECTORIZE_SUBDIR
    path.mkdir(parents=True, exist_ok=True)
    return path

# Загрузка и векторизация CSV-сплитов
def vectorize_splits(splits_dir: Path) -> Dict[str, pd.DataFrame]:
    train_df = load_split(splits_dir, "train")
    valid_df = load_split(splits_dir, "valid")
    test_df = load_split(splits_dir, "test")
    # Вызов основной функции векторизации из vectorize.py
    return vectorize.vectorize(
        train_df=train_df,
        valid_df=valid_df,
        test_df=test_df,
        splits_dir=splits_dir,
    )

# Обучение классификатора RandomForrestClassifier
def train_classifier(results: Dict[str, pd.DataFrame]) -> RandomForestClassifier:
    clf = RandomForestClassifier(
    n_estimators=500,
    max_depth=14,
    min_samples_leaf=2,
    max_features='sqrt',
    class_weight=results["class_weights"],
    bootstrap=True,
    random_state=RANDOM_SEED,
    n_jobs=-1
    )
    X_train = results["X_train"].to_numpy(dtype=np.float32)
    y_train = results["y_train"].to_numpy(dtype=np.int64)

    # Обучение модели
    clf.fit(X_train, y_train)
    return clf

# Расчет метрик на валидационной выборке
def compute_metrics(
    clf: RandomForestClassifier,
    results: Dict[str, pd.DataFrame],
    output_dir: Path,
) -> Dict[str, object]:
    X_test = results["X_test"].to_numpy(dtype=np.float32)
    y_test = results["y_test"].to_numpy(dtype=np.int64)

    # Получение предсказаний
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)

    # Расчет F1-меры (Macro-F1 и F1 для каждого класса)
    macro_f1 = float(f1_score(y_test, y_pred, labels=LABELS, average="macro", zero_division=0))
    per_class_f1 = f1_score(
        y_test,
        y_pred,
        labels=LABELS,
        average=None,
        zero_division=0,
    )
    # Построение матрицы ошибок
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
    
    # Расчет PR-AUC (Precision-Recall) и ROC-AUC для каждого класса
    pr_auc = {}
    roc_auc = {}
    fig, ax = plt.subplots(figsize=(8, 6))
    for idx, label in enumerate(LABELS):
        binary_truth = (y_test == label).astype(int)
        probs = y_proba[:, idx]
        pr_auc[str(label)] = float(average_precision_score(binary_truth, probs))
        roc_auc[str(label)] = float(roc_auc_score(binary_truth, probs))
        fpr, tpr, _ = roc_curve(binary_truth, probs)
        ax.plot(fpr, tpr, label=f"Class {label} (AUC={roc_auc[str(label)]:.3f})")

    # Оформление и сохранение графика ROC-кривой
    ax.plot([0, 1], [0, 1], "k--", label="Random chance")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve (test)")
    ax.legend(loc="lower right")
    roc_path = output_dir / ROC_PLOT_FILENAME
    fig.tight_layout()
    fig.savefig(roc_path, dpi=150)
    plt.close(fig)

    # Возврат словаря с метриками
    return {
        "macro_f1": macro_f1,
        "per_class_f1": {str(label): float(score) for label, score in zip(LABELS, per_class_f1)},
        "confusion_matrix": confusion,
        "pr_auc": pr_auc,
        "roc_auc": roc_auc,
        "class_2_recall": ransomware_recall,
    }


# Сохранение метрик в JSON-файл
def save_metrics(metrics: Dict[str, object], output_dir: Path) -> None:
    metrics_path = output_dir / METRICS_FILENAME
    with metrics_path.open("w", encoding="utf-8") as fh:
        json.dump(metrics, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


def save_test_predictions(
    clf: RandomForestClassifier,
    results: Dict[str, pd.DataFrame],
    test_df: pd.DataFrame,
    output_dir: Path,
) -> None:
    X_test = results["X_test"].to_numpy(dtype=np.float32)
    y_pred = clf.predict(X_test)
    y_proba_raw = clf.predict_proba(X_test)

    test_predictions_df = test_df.copy()
    test_predictions_df["y_pred"] = y_pred.astype(np.int64)

    # Align probabilities with fixed class ids 0/1/2
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
    # Определение и обработка аргументов командной строки
    parser = argparse.ArgumentParser(description="Train RandomForest on vectorized dataset splits.")
    parser.add_argument(
        "splits_dir",
        type=Path,
        help="Directory containing train.csv/valid.csv/test.csv. vectorized/ will be created automatically.",
    )
    parser.add_argument(
        "output_dir",
        type=Path,
        help="Directory to store training artifacts (e.g., metrics_test.json).",
    )
    args = parser.parse_args()

    splits_dir = args.splits_dir.resolve()
    output_dir = ensure_output_dir(args.output_dir.resolve())

    if not splits_dir.is_dir():
        raise FileNotFoundError(f"Splits directory does not exist: {splits_dir}")

    ensure_vectorized_dir(splits_dir)

    # Запуск обучения модели
    results = vectorize_splits(splits_dir)
    clf = train_classifier(results)
    metrics = compute_metrics(clf, results, output_dir)
    save_metrics(metrics, output_dir)
    test_df = load_split(splits_dir, "test")
    save_test_predictions(clf, results, test_df, output_dir)

    print(f"Training complete. Metrics saved to {output_dir / METRICS_FILENAME}")


if __name__ == "__main__":
    main()
