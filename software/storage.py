from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from threading import RLock
from typing import Any

from .models import FileEvent, ProcessProfile


class RuntimeStorage:
    def __init__(self, path: Path | str):
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(
            self.path, check_same_thread=False, timeout=30.0
        )
        self._connection.row_factory = sqlite3.Row
        self._lock = RLock()
        with self._lock:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=NORMAL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._create_schema()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "RuntimeStorage":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def save_event(self, event: FileEvent) -> None:
        classification = event.classification_result
        response = event.response_result
        values = {
            "event_id": event.event_id,
            "event_type": event.event_type.value,
            "timestamp": event.timestamp.isoformat(),
            "file_path": event.file_path,
            "file_extension": event.file_extension,
            "file_size": event.file_size,
            "thread_id": event.thread_id,
            "process_id": event.process_id,
            "process_name": event.process_name,
            "process_path": event.process_path,
            "process_start_time": (
                event.process_start_time.isoformat()
                if event.process_start_time is not None
                else None
            ),
            "process_key": event.process_key,
            "filter_decision": event.filter_decision.value,
            "filter_reason": event.filter_reason,
            "event_priority": event.event_priority.value,
            "stabilization_status": event.stabilization_status.value,
            "stable_file_size": event.stable_file_size,
            "stabilization_attempts": event.stabilization_attempts,
            "stable_mtime": (
                event.stable_mtime.isoformat()
                if event.stable_mtime is not None
                else None
            ),
            "stabilization_error": event.stabilization_error,
            "extraction_status": event.extraction_status.value,
            "features_ref": event.features_ref,
            "features_json": _json(event.features),
            "extraction_error": event.extraction_error,
            "vectorization_status": event.vectorization_status.value,
            "feature_vector_ref": event.feature_vector_ref,
            "feature_vector_json": _json(event.feature_vector),
            "vectorization_error": event.vectorization_error,
            "predicted_class": (
                classification.predicted_class.value if classification else None
            ),
            "benign_probability": (
                classification.benign_probability if classification else None
            ),
            "benign_encrypted_probability": (
                classification.benign_encrypted_probability
                if classification
                else None
            ),
            "ransomware_encrypted_probability": (
                classification.ransomware_encrypted_probability
                if classification
                else None
            ),
            "classifier_version": (
                classification.classifier_version if classification else None
            ),
            "classification_timestamp": (
                classification.classification_timestamp.isoformat()
                if classification
                else None
            ),
            "classification_error": event.classification_error,
            "process_profile_ref": event.process_profile_ref,
            "response_action": (
                response.response_action.value if response else None
            ),
            "requested_action": (
                response.requested_action.value if response else None
            ),
            "executed_action": (
                response.executed_action.value if response else None
            ),
            "response_status": (
                response.response_status.value if response else None
            ),
            "response_timestamp": (
                response.response_timestamp.isoformat() if response else None
            ),
            "response_error": response.response_error if response else None,
        }
        columns = list(values)
        placeholders = ", ".join(f":{column}" for column in columns)
        updates = ", ".join(
            f"{column}=excluded.{column}"
            for column in columns
            if column != "event_id"
        )
        sql = (
            f"INSERT INTO file_events ({', '.join(columns)}) "
            f"VALUES ({placeholders}) "
            f"ON CONFLICT(event_id) DO UPDATE SET {updates}"
        )
        with self._lock, self._connection:
            self._connection.execute(sql, values)

    def save_process(self, profile: ProcessProfile) -> None:
        values = profile.to_dict()
        columns = list(values)
        placeholders = ", ".join(f":{column}" for column in columns)
        updates = ", ".join(
            f"{column}=excluded.{column}"
            for column in columns
            if column != "process_key"
        )
        sql = (
            f"INSERT INTO processes ({', '.join(columns)}) "
            f"VALUES ({placeholders}) "
            f"ON CONFLICT(process_key) DO UPDATE SET {updates}"
        )
        with self._lock, self._connection:
            self._connection.execute(sql, values)

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM file_events WHERE event_id=?", (event_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def get_process(self, process_key: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM processes WHERE process_key=?", (process_key,)
            ).fetchone()
        return dict(row) if row is not None else None

    def count_events(self) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT COUNT(*) AS count FROM file_events"
            ).fetchone()
        return int(row["count"])

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS file_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_extension TEXT,
                file_size INTEGER,
                thread_id INTEGER,
                process_id INTEGER,
                process_name TEXT,
                process_path TEXT,
                process_start_time TEXT,
                process_key TEXT NOT NULL,
                filter_decision TEXT NOT NULL,
                filter_reason TEXT,
                event_priority TEXT NOT NULL,
                stabilization_status TEXT NOT NULL,
                stable_file_size INTEGER,
                stabilization_attempts INTEGER NOT NULL DEFAULT 0,
                stable_mtime TEXT,
                stabilization_error TEXT,
                extraction_status TEXT NOT NULL,
                features_ref TEXT,
                features_json TEXT,
                extraction_error TEXT,
                vectorization_status TEXT NOT NULL,
                feature_vector_ref TEXT,
                feature_vector_json TEXT,
                vectorization_error TEXT,
                predicted_class TEXT,
                benign_probability REAL,
                benign_encrypted_probability REAL,
                ransomware_encrypted_probability REAL,
                classifier_version TEXT,
                classification_timestamp TEXT,
                classification_error TEXT,
                process_profile_ref TEXT,
                response_action TEXT,
                requested_action TEXT,
                executed_action TEXT,
                response_status TEXT,
                response_timestamp TEXT,
                response_error TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_file_events_process_time
                ON file_events(process_key, timestamp);
            CREATE INDEX IF NOT EXISTS idx_file_events_file_path
                ON file_events(file_path);

            CREATE TABLE IF NOT EXISTS processes (
                process_key TEXT PRIMARY KEY,
                process_id INTEGER,
                process_name TEXT NOT NULL,
                process_start_time TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                window_start TEXT NOT NULL,
                window_size INTEGER NOT NULL,
                events_in_window INTEGER NOT NULL,
                classified_events_count INTEGER NOT NULL,
                benign_count INTEGER NOT NULL,
                benign_encrypted_count INTEGER NOT NULL,
                ransomware_encrypted_count INTEGER NOT NULL,
                consecutive_ransomware_hits INTEGER NOT NULL,
                ransomware_ratio REAL NOT NULL,
                max_ransomware_probability REAL NOT NULL,
                avg_ransomware_probability REAL NOT NULL,
                touched_files INTEGER NOT NULL,
                touched_files_unique INTEGER NOT NULL,
                suspicion_score INTEGER NOT NULL,
                threat_level TEXT NOT NULL,
                decision_reason TEXT NOT NULL,
                last_event_id TEXT NOT NULL,
                profile_status TEXT NOT NULL
            );
            """
        )
        self._connection.commit()


def _json(value: Any) -> str | None:
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
