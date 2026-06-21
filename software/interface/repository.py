from __future__ import annotations

import math
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Generic, Iterator, Sequence, TypeVar


class InterfaceDatabaseError(RuntimeError):
    """Base error raised for UI database failures."""


class DatabaseNotFoundError(InterfaceDatabaseError):
    pass


class DatabaseSchemaError(InterfaceDatabaseError):
    pass


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class PageResult(Generic[T]):
    items: tuple[T, ...]
    total: int
    page: int
    page_size: int
    total_pages: int


@dataclass(frozen=True, slots=True)
class ProcessFilters:
    search: str = ""
    threat_levels: tuple[str, ...] = ()
    profile_statuses: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EventFilters:
    search: str = ""
    process_key: str | None = None
    event_types: tuple[str, ...] = ()
    predicted_classes: tuple[str, ...] = ()
    extraction_statuses: tuple[str, ...] = ()
    vectorization_statuses: tuple[str, ...] = ()


PROCESS_REQUIRED_COLUMNS = frozenset(
    {
        "process_key",
        "process_id",
        "process_name",
        "process_start_time",
        "first_seen",
        "last_seen",
        "window_start",
        "window_size",
        "events_in_window",
        "classified_events_count",
        "benign_count",
        "benign_encrypted_count",
        "ransomware_encrypted_count",
        "consecutive_ransomware_hits",
        "ransomware_ratio",
        "max_ransomware_probability",
        "avg_ransomware_probability",
        "touched_files",
        "touched_files_unique",
        "suspicion_score",
        "threat_level",
        "decision_reason",
        "last_event_id",
        "profile_status",
    }
)

EVENT_REQUIRED_COLUMNS = frozenset(
    {
        "event_id",
        "event_type",
        "timestamp",
        "file_path",
        "process_key",
        "process_name",
        "filter_decision",
        "event_priority",
        "stabilization_status",
        "extraction_status",
        "features_json",
        "vectorization_status",
        "feature_vector_json",
        "predicted_class",
        "ransomware_encrypted_probability",
        "response_status",
    }
)

PROCESS_SORTS = {
    "score_desc": "suspicion_score DESC, last_seen DESC",
    "last_seen_desc": "last_seen DESC, process_name ASC",
    "name_asc": "process_name COLLATE NOCASE ASC, last_seen DESC",
    "ransomware_desc": (
        "ransomware_encrypted_count DESC, "
        "max_ransomware_probability DESC, last_seen DESC"
    ),
}

EVENT_SORTS = {
    "timestamp_desc": "timestamp DESC, event_id DESC",
    "ransomware_desc": (
        "ransomware_encrypted_probability DESC, timestamp DESC"
    ),
    "priority_desc": (
        "CASE event_priority "
        "WHEN 'high' THEN 3 WHEN 'normal' THEN 2 ELSE 1 END DESC, "
        "timestamp DESC"
    ),
    "path_asc": "file_path COLLATE NOCASE ASC, timestamp DESC",
}

DISTINCT_COLUMNS = {
    ("processes", "threat_level"),
    ("processes", "profile_status"),
    ("file_events", "event_type"),
    ("file_events", "predicted_class"),
    ("file_events", "extraction_status"),
    ("file_events", "vectorization_status"),
}


class ReadOnlyRepository:
    """Query-only access to the runtime SQLite database."""

    def __init__(self, path: Path | str, *, busy_timeout_ms: int = 5000):
        self.path = Path(path).expanduser().resolve()
        self.busy_timeout_ms = max(0, int(busy_timeout_ms))

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        if not self.path.is_file():
            raise DatabaseNotFoundError(f"База данных не найдена: {self.path}")

        uri = f"{self.path.as_uri()}?mode=ro"
        try:
            connection = sqlite3.connect(
                uri,
                uri=True,
                timeout=self.busy_timeout_ms / 1000,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only=ON")
            connection.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
        except sqlite3.Error as exc:
            raise InterfaceDatabaseError(
                f"Не удалось открыть SQLite только для чтения: {self.path}"
            ) from exc

        try:
            yield connection
        except sqlite3.Error as exc:
            raise InterfaceDatabaseError(
                f"Ошибка чтения SQLite: {exc}"
            ) from exc
        finally:
            connection.close()

    def validate_schema(self) -> None:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type='table' AND name IN ('processes', 'file_events')
                """
            ).fetchall()
            tables = {str(row["name"]) for row in rows}
            missing_tables = {"processes", "file_events"} - tables
            if missing_tables:
                raise DatabaseSchemaError(
                    "В базе отсутствуют таблицы: "
                    + ", ".join(sorted(missing_tables))
                )

            process_columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(processes)"
                ).fetchall()
            }
            event_columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(file_events)"
                ).fetchall()
            }

        missing_process = PROCESS_REQUIRED_COLUMNS - process_columns
        missing_events = EVENT_REQUIRED_COLUMNS - event_columns
        if missing_process or missing_events:
            messages: list[str] = []
            if missing_process:
                messages.append(
                    "processes: " + ", ".join(sorted(missing_process))
                )
            if missing_events:
                messages.append(
                    "file_events: " + ", ".join(sorted(missing_events))
                )
            raise DatabaseSchemaError(
                "Несовместимая схема SQLite; отсутствуют поля: "
                + "; ".join(messages)
            )

    def summary(self) -> dict[str, int]:
        with self._connect() as connection:
            processes = int(
                connection.execute(
                    "SELECT COUNT(*) AS count FROM processes"
                ).fetchone()["count"]
            )
            events = int(
                connection.execute(
                    "SELECT COUNT(*) AS count FROM file_events"
                ).fetchone()["count"]
            )
            critical = int(
                connection.execute(
                    """
                    SELECT COUNT(*) AS count
                    FROM processes
                    WHERE threat_level='critical'
                    """
                ).fetchone()["count"]
            )
            ransomware = int(
                connection.execute(
                    """
                    SELECT COUNT(*) AS count
                    FROM file_events
                    WHERE predicted_class='ransomware-encrypted'
                    """
                ).fetchone()["count"]
            )
        return {
            "processes": processes,
            "events": events,
            "critical_processes": critical,
            "ransomware_events": ransomware,
        }

    def distinct_values(self, table: str, column: str) -> tuple[str, ...]:
        if (table, column) not in DISTINCT_COLUMNS:
            raise ValueError(f"Unsupported distinct field: {table}.{column}")
        sql = (
            f"SELECT DISTINCT {column} AS value FROM {table} "
            f"WHERE {column} IS NOT NULL AND {column} <> '' "
            f"ORDER BY {column}"
        )
        with self._connect() as connection:
            rows = connection.execute(sql).fetchall()
        return tuple(str(row["value"]) for row in rows)

    def list_processes(
        self,
        filters: ProcessFilters | None = None,
        *,
        sort: str = "score_desc",
        page: int = 1,
        page_size: int = 50,
    ) -> PageResult[dict[str, Any]]:
        selected_filters = filters or ProcessFilters()
        where, parameters = _process_where(selected_filters)
        order_by = PROCESS_SORTS.get(sort, PROCESS_SORTS["score_desc"])
        columns = """
            process_key, process_id, process_name, first_seen, last_seen,
            events_in_window, classified_events_count,
            ransomware_encrypted_count, consecutive_ransomware_hits,
            max_ransomware_probability, avg_ransomware_probability,
            touched_files_unique, suspicion_score, threat_level,
            profile_status
        """
        return self._paged_query(
            table="processes",
            columns=columns,
            where=where,
            parameters=parameters,
            order_by=order_by,
            page=page,
            page_size=page_size,
        )

    def get_process(self, process_key: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM processes WHERE process_key=?",
                (process_key,),
            ).fetchone()
        return dict(row) if row is not None else None

    def list_events(
        self,
        filters: EventFilters | None = None,
        *,
        sort: str = "timestamp_desc",
        page: int = 1,
        page_size: int = 50,
    ) -> PageResult[dict[str, Any]]:
        selected_filters = filters or EventFilters()
        where, parameters = _event_where(selected_filters)
        order_by = EVENT_SORTS.get(sort, EVENT_SORTS["timestamp_desc"])
        columns = """
            event_id, timestamp, event_type, file_path, file_extension,
            file_size, process_id, process_name, process_key,
            event_priority, filter_decision, stabilization_status,
            extraction_status, vectorization_status, predicted_class,
            ransomware_encrypted_probability, requested_action,
            executed_action, response_status
        """
        return self._paged_query(
            table="file_events",
            columns=columns,
            where=where,
            parameters=parameters,
            order_by=order_by,
            page=page,
            page_size=page_size,
        )

    def list_process_events(
        self,
        process_key: str,
        *,
        sort: str = "timestamp_desc",
        page: int = 1,
        page_size: int = 50,
    ) -> PageResult[dict[str, Any]]:
        return self.list_events(
            EventFilters(process_key=process_key),
            sort=sort,
            page=page,
            page_size=page_size,
        )

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM file_events WHERE event_id=?",
                (event_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    def _paged_query(
        self,
        *,
        table: str,
        columns: str,
        where: str,
        parameters: Sequence[Any],
        order_by: str,
        page: int,
        page_size: int,
    ) -> PageResult[dict[str, Any]]:
        normalized_size = page_size if page_size in {25, 50, 100} else 50
        with self._connect() as connection:
            count_row = connection.execute(
                f"SELECT COUNT(*) AS count FROM {table}{where}",
                tuple(parameters),
            ).fetchone()
            total = int(count_row["count"])
            total_pages = max(1, math.ceil(total / normalized_size))
            normalized_page = min(max(1, int(page)), total_pages)
            offset = (normalized_page - 1) * normalized_size
            rows = connection.execute(
                f"""
                SELECT {columns}
                FROM {table}{where}
                ORDER BY {order_by}
                LIMIT ? OFFSET ?
                """,
                (*parameters, normalized_size, offset),
            ).fetchall()

        return PageResult(
            items=tuple(dict(row) for row in rows),
            total=total,
            page=normalized_page,
            page_size=normalized_size,
            total_pages=total_pages,
        )


def _process_where(filters: ProcessFilters) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    parameters: list[Any] = []
    if filters.search.strip():
        pattern = f"%{_escape_like(filters.search.strip())}%"
        clauses.append(
            "("
            "process_name LIKE ? ESCAPE '\\' COLLATE NOCASE OR "
            "process_key LIKE ? ESCAPE '\\' COLLATE NOCASE OR "
            "CAST(process_id AS TEXT) LIKE ? ESCAPE '\\'"
            ")"
        )
        parameters.extend((pattern, pattern, pattern))
    _append_in_filter(
        clauses,
        parameters,
        "threat_level",
        filters.threat_levels,
    )
    _append_in_filter(
        clauses,
        parameters,
        "profile_status",
        filters.profile_statuses,
    )
    return _where_sql(clauses), parameters


def _event_where(filters: EventFilters) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    parameters: list[Any] = []
    if filters.search.strip():
        pattern = f"%{_escape_like(filters.search.strip())}%"
        clauses.append(
            "("
            "file_path LIKE ? ESCAPE '\\' COLLATE NOCASE OR "
            "process_name LIKE ? ESCAPE '\\' COLLATE NOCASE OR "
            "process_key LIKE ? ESCAPE '\\' COLLATE NOCASE OR "
            "event_id LIKE ? ESCAPE '\\' COLLATE NOCASE"
            ")"
        )
        parameters.extend((pattern, pattern, pattern, pattern))
    if filters.process_key is not None:
        clauses.append("process_key=?")
        parameters.append(filters.process_key)
    _append_in_filter(
        clauses,
        parameters,
        "event_type",
        filters.event_types,
    )
    _append_in_filter(
        clauses,
        parameters,
        "predicted_class",
        filters.predicted_classes,
    )
    _append_in_filter(
        clauses,
        parameters,
        "extraction_status",
        filters.extraction_statuses,
    )
    _append_in_filter(
        clauses,
        parameters,
        "vectorization_status",
        filters.vectorization_statuses,
    )
    return _where_sql(clauses), parameters


def _append_in_filter(
    clauses: list[str],
    parameters: list[Any],
    column: str,
    values: Sequence[str],
) -> None:
    normalized = tuple(str(value) for value in values if str(value))
    if not normalized:
        return
    placeholders = ", ".join("?" for _ in normalized)
    clauses.append(f"{column} IN ({placeholders})")
    parameters.extend(normalized)


def _where_sql(clauses: Sequence[str]) -> str:
    return f" WHERE {' AND '.join(clauses)}" if clauses else ""


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
