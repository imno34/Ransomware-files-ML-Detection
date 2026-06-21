from __future__ import annotations

import numpy as np
import pandas as pd

from training import vectorize as training_vectorize

from .bundle import RuntimeBundle
from .models import FileEvent, ProcessingStatus


class FeatureVectorizer:
    def __init__(self, bundle: RuntimeBundle):
        self.bundle = bundle

    def vectorize(self, event: FileEvent) -> FileEvent:
        if event.features is None:
            event.vectorization_status = ProcessingStatus.FAILED
            event.vectorization_error = "features are unavailable"
            return event
        try:
            raw = pd.DataFrame(
                [{name: event.features.get(name) for name in self.bundle.feature_list}],
                columns=self.bundle.feature_list,
            )
            frame = training_vectorize.coerce_frame(raw, self.bundle.dtype_map)
            frame = frame.fillna(dict(self.bundle.fill_values))
            if frame.isna().any().any():
                missing = frame.columns[frame.isna().any()].tolist()
                raise ValueError(f"unfilled values remain for features: {missing}")
            training_vectorize.log_transform_byte_chi2(frame)
            if self.bundle.scaler_columns:
                values = frame[list(self.bundle.scaler_columns)].astype(
                    np.float64
                ).to_numpy(copy=False)
                scaled = self.bundle.scaler.transform(values)
                for index, name in enumerate(self.bundle.scaler_columns):
                    frame[name] = scaled[:, index]
            training_vectorize.cast_column_dtypes(frame, self.bundle.dtype_map)
            event.feature_vector = (
                frame[list(self.bundle.feature_list)]
                .iloc[0]
                .to_numpy(dtype=np.float32)
                .astype(float)
                .tolist()
            )
            event.feature_vector_ref = (
                f"sqlite:file_events/{event.event_id}#feature_vector_json"
            )
            event.vectorization_status = ProcessingStatus.SUCCESS
            event.vectorization_error = None
        except Exception as exc:
            event.feature_vector = None
            event.vectorization_status = ProcessingStatus.FAILED
            event.vectorization_error = f"{type(exc).__name__}: {exc}"
        return event

    def as_model_frame(self, event: FileEvent) -> pd.DataFrame:
        if event.feature_vector is None:
            raise ValueError("event has no feature vector")
        return pd.DataFrame(
            [event.feature_vector],
            columns=self.bundle.feature_list,
            dtype=np.float32,
        )
