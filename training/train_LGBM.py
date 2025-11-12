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

# Определение меток классов на основе артефакта после векторизации
LABELS = sorted(vectorize.LABEL_MAP.values())
# Имена файлов для сохранения результатов
METRICS_FILENAME = "metrics_valid.json"
ROC_PLOT_FILENAME = "roc_curve_lgbm.png"

# Загрузка CSV-файла сплита (train/valid/test)
def load_split(splits_dir: Path, split_name: str) -> pd.DataFrame:
    csv_path = splits_dir / f"{split_name}.csv"
    if not csv_path.is_file():
        raise FileNotFoundError(f"Файл сплита не найден: {csv_path}")
    return pd.read_csv(csv_path)

# Гарантия существования выходной директории
def ensure_output_dir(path: Path) -> Path:
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
# Обучение классификатора LightGBM
def train_classifier(results: Dict[str, pd.DataFrame]) -> LGBMClassifier:
    clf = LGBMClassifier(
        num_leaves=64,
        n_estimators=700,
        learning_rate=0.05,
        max_depth=-1,
        subsample=0.9,
        colsample_bytree=0.9,
        class_weight=results["class_weights"],  # Использование весов классов
        random_state=42,
    )
    X_train = results["X_train"]
    y_train = results["y_train"].to_numpy(dtype=np.int64)
    
    # Обучение модели
    clf.fit(X_train, y_train)
    return clf

# Расчет метрик на валидационной выборке
def compute_metrics(
    clf: LGBMClassifier,
    results: Dict[str, pd.DataFrame],
    output_dir: Path,
) -> Dict[str, object]:
    X_valid = results["X_valid"]
    y_valid = results["y_valid"].to_numpy(dtype=np.int64)

    # Получение предсказаний
    y_pred = clf.predict(X_valid)
    y_proba = clf.predict_proba(X_valid)

    # Расчет F1-меры (Macro-F1 и F1 для каждого класса)
    macro_f1 = float(f1_score(y_valid, y_pred, labels=LABELS, average="macro", zero_division=0))
    per_class_f1 = f1_score(
        y_valid,
        y_pred,
        labels=LABELS,
        average=None,
        zero_division=0,
    )
    # Построение матрицы ошибок
    confusion = confusion_matrix(y_valid, y_pred, labels=LABELS).astype(int).tolist()

    # Расчет PR-AUC (Precision-Recall) и ROC-AUC для каждого класса
    pr_auc = {}
    roc_auc = {}
    fig, ax = plt.subplots(figsize=(8, 6))
    for idx, label in enumerate(LABELS):
        binary_truth = (y_valid == label).astype(int)
        probs = y_proba[:, idx]
        pr_auc[str(label)] = float(average_precision_score(binary_truth, probs))
        roc_auc[str(label)] = float(roc_auc_score(binary_truth, probs))
        # Построение ROC-кривой
        fpr, tpr, _ = roc_curve(binary_truth, probs)
        ax.plot(fpr, tpr, label=f"Class {label} (AUC={roc_auc[str(label)]:.3f})")

    # Оформление и сохранение графика ROC-кривой
    ax.plot([0, 1], [0, 1], "k--", label="Random chance")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curve (validation)")
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
    }

# Сохранение метрик в JSON-файл
def save_metrics(metrics: Dict[str, object], output_dir: Path) -> None:
    metrics_path = output_dir / METRICS_FILENAME
    with metrics_path.open("w", encoding="utf-8") as fh:
        json.dump(metrics, fh, ensure_ascii=False, indent=2)
        fh.write("\n")

def main() -> None:
    # Определение и обработка аргументов командной строки
    parser = argparse.ArgumentParser(description="Train LightGBM on vectorized dataset splits.")
    parser.add_argument(
        "splits_dir",
        type=Path,
        help="Directory containing train/valid/test CSVs and the vectorized/ subdirectory.",
    )
    parser.add_argument(
        "output_dir",
        type=Path,
        help="Directory to store training artifacts (metrics_valid.json).",
    )
    args = parser.parse_args()

    splits_dir = args.splits_dir.resolve()
    output_dir = ensure_output_dir(args.output_dir.resolve())

    if not splits_dir.is_dir():
        raise FileNotFoundError(f"Директория сплитов не найдена: {splits_dir}")

    # Запуск обучения модели
    results = vectorize_splits(splits_dir)
    clf = train_classifier(results)
    metrics = compute_metrics(clf, results, output_dir)
    save_metrics(metrics, output_dir)

    print(f"Обучение завершено. Метрики сохранены в {output_dir / METRICS_FILENAME}")


if __name__ == "__main__":
    main()