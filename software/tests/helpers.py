from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from software.config import (
    FilterConfig,
    LoggingConfig,
    ModelConfig,
    MonitorConfig,
    ProcessingConfig,
    RuntimeConfig,
    ScoringConfig,
    StabilizationConfig,
    StorageConfig,
)
from software.models import EventType, FileEvent


NOW = datetime(2026, 6, 18, 10, 0, tzinfo=timezone.utc)


class DummyModel:
    classes_ = [0, 1, 2]

    def predict(self, frame):
        return [2] * len(frame)

    def predict_proba(self, frame):
        return [[0.01, 0.04, 0.95] for _ in range(len(frame))]


class IdentityScaler:
    def transform(self, values):
        return values


def make_event(path: Path, **changes) -> FileEvent:
    event = FileEvent(
        event_id="event-1",
        event_type=EventType.MODIFIED,
        timestamp=NOW,
        file_path=str(path),
        file_extension=path.suffix.lower(),
        file_size=path.stat().st_size if path.exists() else None,
        process_id=1234,
        process_name="sample.exe",
        process_start_time=NOW,
        process_key="1234:test",
    )
    return replace(event, **changes)


def make_config(root: Path, *, workers: int = 2) -> RuntimeConfig:
    return RuntimeConfig(
        source_path=root / "runtime.yaml",
        monitor=MonitorConfig(monitored_directories=(root,)),
        filters=FilterConfig(
            supported_extensions=frozenset({".bin", ".txt", ".pdf"}),
            max_file_size_bytes=100 * 1024 * 1024,
        ),
        stabilization=StabilizationConfig(
            interval_ms=1, stable_checks=1, max_attempts=2
        ),
        processing=ProcessingConfig(
            queue_size=16, workers=workers, extraction_fallback=True
        ),
        scoring=ScoringConfig(window_seconds=30),
        storage=StorageConfig(path=root / "runtime.sqlite3"),
        model=ModelConfig(bundle_path=root / "bundle.joblib"),
        logging=LoggingConfig(path=root / "logs"),
    )


def make_small_bundle():
    from software.bundle import RuntimeBundle

    return RuntimeBundle(
        model=DummyModel(),
        feature_list=("value",),
        dtype_map={"value": "float"},
        fill_values={"value": 0.0},
        scaler=IdentityScaler(),
        scaler_columns=("value",),
        label_map={
            "benign": 0,
            "benign-encrypted": 1,
            "ransomware-encrypted": 2,
        },
        model_version="test-model",
        feature_schema_hash="test-only",
    )
