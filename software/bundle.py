from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import joblib

from featurizers.extract import collect_schema, load_cfg
from training import vectorize as training_vectorize


REQUIRED_BUNDLE_KEYS = {
    "model",
    "feature_list",
    "dtype_map",
    "fill_values",
    "scaler",
    "scaler_columns",
    "label_map",
    "model_version",
    "feature_schema_hash",
}


class BundleValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RuntimeBundle:
    model: Any
    feature_list: tuple[str, ...]
    dtype_map: Mapping[str, str]
    fill_values: Mapping[str, Any]
    scaler: Any
    scaler_columns: tuple[str, ...]
    label_map: Mapping[str, int]
    model_version: str
    feature_schema_hash: str

    @classmethod
    def load(cls, path: Path | str) -> "RuntimeBundle":
        bundle_path = Path(path).expanduser().resolve()
        if not bundle_path.is_file():
            raise BundleValidationError(f"ML bundle not found: {bundle_path}")
        try:
            payload = joblib.load(bundle_path)
        except Exception as exc:
            raise BundleValidationError(f"Cannot load ML bundle: {exc}") from exc
        if not isinstance(payload, Mapping):
            raise BundleValidationError("ML bundle root must be a mapping")
        missing = sorted(REQUIRED_BUNDLE_KEYS - set(payload))
        if missing:
            raise BundleValidationError(f"ML bundle is missing keys: {missing}")
        try:
            bundle = cls(
                model=payload["model"],
                feature_list=tuple(
                    str(item) for item in payload["feature_list"]
                ),
                dtype_map={
                    str(key): str(value).lower()
                    for key, value in payload["dtype_map"].items()
                },
                fill_values=dict(payload["fill_values"]),
                scaler=payload["scaler"],
                scaler_columns=tuple(
                    str(item) for item in payload["scaler_columns"]
                ),
                label_map={
                    str(key): int(value)
                    for key, value in payload["label_map"].items()
                },
                model_version=str(payload["model_version"]),
                feature_schema_hash=str(payload["feature_schema_hash"]),
            )
            bundle.validate()
            return bundle
        except BundleValidationError:
            raise
        except Exception as exc:
            raise BundleValidationError(
                f"ML bundle validation failed: {type(exc).__name__}: {exc}"
            ) from exc

    def validate(self) -> None:
        from lightgbm import LGBMClassifier
        from sklearn.preprocessing import StandardScaler

        if not isinstance(self.model, LGBMClassifier):
            raise BundleValidationError(
                "Bundle model must be a fitted lightgbm.LGBMClassifier"
            )
        expected_features, expected_types = training_vectorize.load_numeric_schema()
        if list(self.feature_list) != expected_features:
            raise BundleValidationError(
                "Bundle feature_list does not match the current numeric feature schema"
            )
        bundle_types = {
            name: self.dtype_map.get(name, "") for name in self.feature_list
        }
        schema_types = {
            name: expected_types.get(name, "") for name in self.feature_list
        }
        if bundle_types != schema_types:
            raise BundleValidationError("Bundle dtype_map does not match features.yaml")
        missing_fill = [
            name for name in self.feature_list if name not in self.fill_values
        ]
        if missing_fill:
            raise BundleValidationError(
                f"Bundle fill_values is missing features: {missing_fill}"
            )
        invalid_scaler_columns = [
            name for name in self.scaler_columns if name not in self.feature_list
        ]
        if invalid_scaler_columns:
            raise BundleValidationError(
                f"Bundle scaler_columns contains unknown features: {invalid_scaler_columns}"
            )
        expected_scaler_columns = training_vectorize.scaler_columns(
            self.feature_list, self.dtype_map
        )
        if list(self.scaler_columns) != expected_scaler_columns:
            raise BundleValidationError(
                "Bundle scaler_columns does not match training.vectorize.scaler_columns()"
            )
        if self.scaler_columns and not isinstance(self.scaler, StandardScaler):
            raise BundleValidationError(
                "Bundle scaler must be a fitted sklearn.preprocessing.StandardScaler"
            )
        if self.scaler_columns and not hasattr(self.scaler, "mean_"):
            raise BundleValidationError("Bundle StandardScaler is not fitted")
        scaler_feature_count = getattr(self.scaler, "n_features_in_", None)
        if (
            self.scaler_columns
            and scaler_feature_count is not None
            and int(scaler_feature_count) != len(self.scaler_columns)
        ):
            raise BundleValidationError(
                "Bundle StandardScaler feature count does not match scaler_columns"
            )
        scaler_feature_names = getattr(self.scaler, "feature_names_in_", None)
        if scaler_feature_names is not None and [
            str(value) for value in scaler_feature_names
        ] != list(self.scaler_columns):
            raise BundleValidationError(
                "Bundle StandardScaler feature order does not match scaler_columns"
            )
        expected_labels = dict(training_vectorize.LABEL_MAP)
        if dict(self.label_map) != expected_labels:
            raise BundleValidationError(
                f"Bundle label_map must equal {expected_labels}"
            )
        if not callable(getattr(self.model, "predict", None)):
            raise BundleValidationError("Bundle model must provide predict()")
        if not callable(getattr(self.model, "predict_proba", None)):
            raise BundleValidationError("Bundle model must provide predict_proba()")
        classes = getattr(self.model, "classes_", None)
        if classes is None:
            raise BundleValidationError("Bundle model is not fitted: classes_ is missing")
        if sorted(int(value) for value in classes) != sorted(expected_labels.values()):
            raise BundleValidationError(
                f"Bundle model classes must be {sorted(expected_labels.values())}"
            )
        model_feature_count = getattr(self.model, "n_features_in_", None)
        if (
            model_feature_count is not None
            and int(model_feature_count) != len(self.feature_list)
        ):
            raise BundleValidationError(
                "Bundle model feature count does not match feature_list"
            )
        model_feature_names = getattr(self.model, "feature_name_", None)
        if model_feature_names:
            normalized_names = [str(value) for value in model_feature_names]
            generated_names = [
                f"Column_{index}" for index in range(len(self.feature_list))
            ]
            if (
                normalized_names != generated_names
                and normalized_names != list(self.feature_list)
            ):
                raise BundleValidationError(
                    "Bundle model feature order does not match feature_list"
                )
        current_hash = current_feature_schema_hash()
        if self.feature_schema_hash != current_hash:
            raise BundleValidationError(
                "Bundle feature_schema_hash does not match the current features.yaml "
                f"(expected {current_hash}, got {self.feature_schema_hash})"
            )
        if not self.model_version.strip():
            raise BundleValidationError("Bundle model_version cannot be empty")


def current_feature_schema_hash() -> str:
    cfg = load_cfg()
    columns, type_map = collect_schema(cfg)
    numeric_features, numeric_types = training_vectorize.load_numeric_schema()
    canonical = {
        "all_features": [
            {"name": name, "type": type_map.get(name, "")} for name in columns
        ],
        "numeric_features": [
            {"name": name, "type": numeric_types.get(name, "")}
            for name in numeric_features
        ],
    }
    encoded = json.dumps(
        canonical, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def bundle_summary(bundle: RuntimeBundle) -> dict[str, Any]:
    return {
        "model_type": type(bundle.model).__name__,
        "model_version": bundle.model_version,
        "feature_count": len(bundle.feature_list),
        "scaler_feature_count": len(bundle.scaler_columns),
        "classes": [int(value) for value in bundle.model.classes_],
        "feature_schema_hash": bundle.feature_schema_hash,
    }
