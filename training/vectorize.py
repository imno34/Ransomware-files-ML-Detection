#vectorize.py

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, List, Mapping, Sequence, Tuple

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_class_weight

# Добавление родительской директории в sys.path для импорта featurizers
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from featurizers.extract import collect_schema, load_cfg

# Служебные колонки, которые не являются признаками для модели
SERVICE_COLUMNS = {"path", "gt_class", "sequence_id", "orig_ext", "curr_ext"}
# Кодирование текстовых меток классов в числовые
LABEL_MAP = {
    "benign": 0,
    "benign-encrypted": 1,
    "ransomware-encrypted": 2,
}
# Имена колонок для специальной обработки
PDF_VERSION_COLUMN = "pdf_version"
BYTE_CHI2_COLUMN = "byte_chi2"
# Поддиректория для сохранения векторизованных данных
VECTORIZE_SUBDIR = "vectorized"

# Импутация пропусков
BOOL_FALLBACK = False
INT_FALLBACK = 0.0
FLOAT_FALLBACK = 0.0

__all__ = ["vectorize"]

# Ф-ция загрузки схемы из файла конфигурации, фильтрация только числовых признаков
def load_numeric_schema() -> Tuple[List[str], Dict[str, str]]:
    cfg = load_cfg()
    columns, type_map = collect_schema(cfg)
    numeric_cols: List[str] = []
    numeric_types: Dict[str, str] = {}
    for col in columns:
        col_type = type_map.get(col, "").lower()
        # Исключение строковых и служебных колонок
        if col_type == "string":
            continue
        if col in SERVICE_COLUMNS:
            continue
        numeric_cols.append(col)
        numeric_types[col] = col_type
    return numeric_cols, numeric_types

#Проверка, что в датафрейме присутствуют все колонки из файла конфигурации
def ensure_required_columns(df: pd.DataFrame, feature_list: Sequence[str], split_name: str) -> None:
    missing = [col for col in feature_list if col not in df.columns]
    if missing:
        raise ValueError(f"Сплит '{split_name}' не содержит колонки: {missing}")
    if "gt_class" not in df.columns:
        raise ValueError(f"Сплит '{split_name}' должен содержать 'gt_class'")

#Приведение колонок DataFrame к числовым типам (bool, numeric)
def coerce_frame(df: pd.DataFrame, dtype_map: Mapping[str, str]) -> pd.DataFrame:
    coerced = {}
    for col in df.columns:
        col_type = dtype_map.get(col, "")
        if col_type == "bool":
            # Приведение к булевому типу
            coerced[col] = coerce_bool_series(df[col]).astype('boolean')
        else:
            # Приведение к числовому, ошибки импутируются на NaN
            coerced[col] = pd.to_numeric(df[col], errors="coerce")
    return pd.DataFrame(coerced, columns=df.columns)

#Приведение значений (str, int, float) к bool или NaN
def coerce_bool_series(series: pd.Series) -> pd.Series:
    def to_bool(value: object) -> float | bool:
        if pd.isna(value):
            return np.nan
        if isinstance(value, bool):
            return value
        # Обработка 0, 1
        if isinstance(value, (int, np.integer)):
            if value in (0, 1):
                return bool(value)
        # Обработка 0.0, 1.0
        if isinstance(value, (float, np.floating)):
            if np.isnan(value):
                return np.nan
            if value in (0.0, 1.0):
                return bool(int(value))
        # Обработка "true", "false", "t", "f", "1", "0"
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"true", "t", "1", "yes"}:
                return True
            if lowered in {"false", "f", "0", "no", ""}:
                return False
        return np.nan

    return series.map(to_bool)

# Расчет значений для заполнения пропусков - рассчитывается только на train выборке
def compute_fill_values(train_df: pd.DataFrame, dtype_map: Mapping[str, str]) -> Dict[str, object]:
    fill_values: Dict[str, object] = {}
    for col in train_df.columns:
        # pdf_version всегда заполняется 0.0 (исключение)
        if col == PDF_VERSION_COLUMN:
            fill_values[col] = 0.0
            continue

        col_type = dtype_map.get(col, "")
        series = train_df[col]
        if col_type == "bool":
            # Для bool берется мода
            fill_values[col] = bool_mode(series)
        elif col_type in {"int", "float"}:
            # Для int/float берется медиана
            filled = series.dropna()
            if filled.empty:
                fill_values[col] = FLOAT_FALLBACK
            else:
                fill_values[col] = float(filled.median())
        else:
            fill_values[col] = FLOAT_FALLBACK
    return fill_values

#Расчет моды для булевых типов
def bool_mode(series: pd.Series) -> bool:
    non_null = series.dropna()
    if non_null.empty:
        return BOOL_FALLBACK
    counts = non_null.value_counts()
    max_count = counts.max()
    top_values = [value for value, count in counts.items() if count == max_count]
    # При равенстве частот ставим False
    if len(top_values) > 1:
        return False
    return bool(top_values[0])

# Применение логарифмического преобразования к критерию Пирсона
def log_transform_byte_chi2(*frames: pd.DataFrame) -> None:
    for frame in frames:
        if BYTE_CHI2_COLUMN in frame.columns:
            clipped = frame[BYTE_CHI2_COLUMN].clip(lower=0)
            frame[BYTE_CHI2_COLUMN] = np.log1p(clipped.astype(np.float32))

# Определение списка колонок для масштабирования (только числовые с исключением pdf_version)
def scaler_columns(feature_list: Sequence[str], dtype_map: Mapping[str, str]) -> List[str]:
    cols: List[str] = []
    for col in feature_list:
        if col == PDF_VERSION_COLUMN:
            continue
        col_type = dtype_map.get(col, "")
        if col_type in {"int", "float"}:
            cols.append(col)
    return cols

# Ф-ция масштабирования
def fit_transform_scaler(
    train_df: pd.DataFrame,
    valid_df: pd.DataFrame,
    test_df: pd.DataFrame,
    columns: Sequence[str],
) -> None:
    if not columns:
        return
    scaler = StandardScaler()
    
    # Преобразование в numpy для производительности
    train_vals = train_df[columns].astype(np.float64).to_numpy(copy=False)
    valid_vals = valid_df[columns].astype(np.float64).to_numpy(copy=False)
    test_vals = test_df[columns].astype(np.float64).to_numpy(copy=False)

    # Масштабирование на train выборке
    scaler.fit(train_vals)
    # Заполнение по всем сплитам
    train_scaled = scaler.transform(train_vals)
    valid_scaled = scaler.transform(valid_vals)
    test_scaled = scaler.transform(test_vals)

    # Запись отмасштабированных значений обратно в датафрейм
    for idx, col in enumerate(columns):
        train_df[col] = train_scaled[:, idx]
        valid_df[col] = valid_scaled[:, idx]
        test_df[col] = test_scaled[:, idx]

# Финальное приведение типов
def cast_column_dtypes(df: pd.DataFrame, dtype_map: Mapping[str, str]) -> None:
    for col in df.columns:
        col_type = dtype_map.get(col, "")
        if col == PDF_VERSION_COLUMN or col_type in {"int", "float"}:
            df[col] = df[col].astype(np.float32)
        elif col_type == "bool":
            # bool сохраняется как uint8 (0 или 1)
            df[col] = df[col].astype(np.uint8)
        else:
            df[col] = df[col].astype(np.float32)

# Кодирование текстовых меток (gt_class) в числовые (0, 1, 2)
def encode_targets(df: pd.DataFrame, split_name: str) -> pd.Series:
    if "gt_class" not in df.columns:
        raise ValueError(f"Сплит '{split_name}' не содержит 'gt_class'")
    encoded = df["gt_class"].map(LABEL_MAP)
    # Проверка на неизвестные метки
    if encoded.isna().any():
        missing = df.loc[encoded.isna(), "gt_class"].unique()
        raise ValueError(f"Неизвестные метки в сплите '{split_name}': {missing}")
    return encoded.astype(np.int64)

# Расчет весов классов для балансировки
def compute_class_weights(y_train: pd.Series) -> Dict[int, float]:
    """Расчет весов классов для балансировки (важно для RandomForest и др.)"""
    y_values = y_train.to_numpy(dtype=np.int64)
    classes = np.array(sorted(LABEL_MAP.values()), dtype=np.int64)
    try:
        # Использование встроенной функции scikit-learn
        weights = compute_class_weight(class_weight="balanced", classes=classes, y=y_values)
    except ValueError:
        # Ручной подсчет в случае, если класс не попал в выборку y_train
        weights = fallback_class_weights(y_values, classes)
    return {int(cls): float(weight) for cls, weight in zip(classes, weights)}

# Ручной расчет весов классов
def fallback_class_weights(y_values: np.ndarray, classes: np.ndarray) -> np.ndarray:
    counts = {cls: 0 for cls in classes}
    for value in y_values:
        counts[value] = counts.get(value, 0) + 1
    total = len(y_values)
    n_classes = len(classes)
    weights: List[float] = []
    for cls in classes:
        count = counts.get(int(cls), 0)
        if count == 0:
            weights.append(0.0)
        else:
            # Формула балансировки
            weights.append(total / (n_classes * count))
    return np.asarray(weights, dtype=np.float64)

#Сохранение векторизованных данных и метаданных в файлы
def persist_artifacts(
    vectorized_dir: Path,
    X_train: pd.DataFrame,
    X_valid: pd.DataFrame,
    X_test: pd.DataFrame,
    y_train: pd.Series,
    y_valid: pd.Series,
    y_test: pd.Series,
    feature_list: Sequence[str],
    class_weights: Mapping[int, float],
) -> None:
    
    # Сохранение признаков (X) в бинарном формате .npy
    np.save(vectorized_dir / "X_train.npy", frame_to_structured_array(X_train))
    np.save(vectorized_dir / "X_valid.npy", frame_to_structured_array(X_valid))
    np.save(vectorized_dir / "X_test.npy", frame_to_structured_array(X_test))

    # Сохранение меток (y) в бинарном формате .npy
    np.save(vectorized_dir / "y_train.npy", y_train.to_numpy(dtype=np.int64))
    np.save(vectorized_dir / "y_valid.npy", y_valid.to_numpy(dtype=np.int64))
    np.save(vectorized_dir / "y_test.npy", y_test.to_numpy(dtype=np.int64))

    # Сохранение метаданных в .json
    save_json(vectorized_dir / "feature_list.json", list(feature_list))
    save_json(vectorized_dir / "label_map.json", LABEL_MAP)
    save_json(vectorized_dir / "class_weights.json", {int(k): v for k, v in class_weights.items()})

# Преобразование DataFrame в структурированный массив numpy (для .npy артефактов)
def frame_to_structured_array(df: pd.DataFrame) -> np.ndarray:
    dtype = []
    for col in df.columns:
        if df[col].dtype == np.uint8:
            dtype.append((col, np.uint8))
        else:
            dtype.append((col, np.float32))
    data = np.empty(df.shape[0], dtype=dtype)
    for col in df.columns:
        data[col] = df[col].to_numpy()
    return data

# Вспомогательная функция для сохранения JSON с форматированием
def save_json(path: Path, payload: object) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=True, indent=2)
        handle.write("\n")

# Главная функция векторизации датасета и сохранения артефактов
def vectorize(
    train_df: pd.DataFrame,
    valid_df: pd.DataFrame,
    test_df: pd.DataFrame,
    splits_dir: Path | str,
) -> Dict[str, pd.DataFrame]:

    vectorized_dir = Path(splits_dir) / VECTORIZE_SUBDIR
    if not vectorized_dir.is_dir():
        raise FileNotFoundError(f"Ожидаемая директория не найдена: {vectorized_dir}")

    # Загрузка схемы числовых признаков из файла конфигурации
    feature_list, dtype_map = load_numeric_schema()
    if not feature_list:
        raise RuntimeError("В схеме не определены числовые признаки")

    # Проверка наличия всех необходимых колонок
    for split_name, df in (("train", train_df), ("valid", valid_df), ("test", test_df)):
        ensure_required_columns(df, feature_list, split_name)

    # 1. Приведение типов
    train_X = coerce_frame(train_df[feature_list].copy(), dtype_map)
    valid_X = coerce_frame(valid_df[feature_list].copy(), dtype_map)
    test_X = coerce_frame(test_df[feature_list].copy(), dtype_map)

    # 2. Импутация пропусков
    fill_values = compute_fill_values(train_X, dtype_map)
    # Применение значений ко всем сплитам
    train_X = train_X.fillna(fill_values)
    valid_X = valid_X.fillna(fill_values)
    test_X = test_X.fillna(fill_values)

    # 3. Логарифмическое преобразование
    log_transform_byte_chi2(train_X, valid_X, test_X)

    # 4. Стандартзизация
    scaler_cols = scaler_columns(feature_list, dtype_map)
    fit_transform_scaler(train_X, valid_X, test_X, scaler_cols)

    # 5. Приведение типов
    cast_column_dtypes(train_X, dtype_map)
    cast_column_dtypes(valid_X, dtype_map)
    cast_column_dtypes(test_X, dtype_map)

    # 6. Кодирование целевых переменных
    y_train = encode_targets(train_df, "train")
    y_valid = encode_targets(valid_df, "valid")
    y_test = encode_targets(test_df, "test")

    # 7. Расчет весов классов
    class_weights = compute_class_weights(y_train)

    # 8. Сохранение артефактов
    persist_artifacts(
        vectorized_dir,
        train_X,
        valid_X,
        test_X,
        y_train,
        y_valid,
        y_test,
        feature_list,
        class_weights,
    )

    # Возврат векторизованных данных
    return {
        "X_train": train_X,
        "X_valid": valid_X,
        "X_test": test_X,
        "y_train": y_train,
        "y_valid": y_valid,
        "y_test": y_test,
        "feature_list": feature_list,
        "class_weights": class_weights,
    }