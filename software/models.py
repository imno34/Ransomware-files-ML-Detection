from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_datetime(value: Any, *, default: datetime | None = None) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        numeric = float(value)
        if numeric > 100_000_000_000_000:
            # ETW commonly exposes FILETIME: 100 ns ticks since 1601-01-01.
            numeric = (numeric - 116_444_736_000_000_000) / 10_000_000
        try:
            parsed = datetime.fromtimestamp(numeric, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return default or utc_now()
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return default or utc_now()
    else:
        return default or utc_now()
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class StringEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class EventType(StringEnum):
    CREATED = "created"
    MODIFIED = "modified"
    MOVED = "moved"
    DELETED = "deleted"


class FilterDecision(StringEnum):
    PENDING = "pending"
    PASS = "pass"
    DROP = "drop"
    CONTEXT_ONLY = "context_only"


class EventPriority(StringEnum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"


class StabilizationStatus(StringEnum):
    PENDING = "pending"
    STABLE = "stable"
    FAILED = "failed"
    SKIPPED = "skipped"


class ProcessingStatus(StringEnum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class PredictedClass(StringEnum):
    BENIGN = "benign"
    BENIGN_ENCRYPTED = "benign-encrypted"
    RANSOMWARE_ENCRYPTED = "ransomware-encrypted"


class ThreatLevel(StringEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ProfileStatus(StringEnum):
    ACTIVE = "active"
    EXPIRED = "expired"


class ResponseAction(StringEnum):
    LOG = "log"
    WARN = "warn"
    SUSPEND = "suspend"
    TERMINATE = "terminate"


class ResponseStatus(StringEnum):
    LOGGED = "logged"
    FAILED = "failed"


@dataclass(slots=True)
class ClassificationResult:
    predicted_class: PredictedClass
    benign_probability: float
    benign_encrypted_probability: float
    ransomware_encrypted_probability: float
    classifier_version: str
    classification_timestamp: datetime = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass(slots=True)
class ResponseResult:
    response_action: ResponseAction
    requested_action: ResponseAction
    executed_action: ResponseAction
    response_status: ResponseStatus
    response_timestamp: datetime = field(default_factory=utc_now)
    response_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


@dataclass(slots=True)
class FileEvent:
    event_id: str
    event_type: EventType
    timestamp: datetime
    file_path: str
    file_extension: str = ""
    file_size: int | None = None
    thread_id: int | None = None
    process_id: int | None = None
    process_name: str = "unknown"
    process_path: str | None = None
    process_start_time: datetime | None = None
    process_key: str = "unknown"

    filter_decision: FilterDecision = FilterDecision.PENDING
    filter_reason: str | None = None
    event_priority: EventPriority = EventPriority.NORMAL

    stabilization_status: StabilizationStatus = StabilizationStatus.PENDING
    stable_file_size: int | None = None
    stabilization_attempts: int = 0
    stable_mtime: datetime | None = None
    stabilization_error: str | None = None

    extraction_status: ProcessingStatus = ProcessingStatus.PENDING
    features_ref: str | None = None
    extraction_error: str | None = None
    features: dict[str, Any] | None = field(default=None, repr=False)

    vectorization_status: ProcessingStatus = ProcessingStatus.PENDING
    feature_vector_ref: str | None = None
    vectorization_error: str | None = None
    feature_vector: list[float] | None = field(default=None, repr=False)

    classification_result: ClassificationResult | None = None
    classification_error: str | None = None
    process_profile_ref: str | None = None
    response_result: ResponseResult | None = None

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "FileEvent":
        event_type = EventType(str(payload.get("event_type", "modified")).lower())
        file_path = str(payload["file_path"])
        process_id_raw = payload.get("process_id")
        process_id = int(process_id_raw) if process_id_raw not in (None, "", "unknown") else None
        start_time_raw = payload.get("process_start_time")
        process_start_time = (
            parse_datetime(start_time_raw) if start_time_raw not in (None, "") else None
        )
        process_name = str(payload.get("process_name") or "unknown")
        process_key = str(payload.get("process_key") or "")
        if not process_key:
            if process_id is not None and process_start_time is not None:
                process_key = build_process_key(process_id, process_start_time)
            elif process_id is not None:
                process_key = f"{process_id}:unknown"
            else:
                process_key = f"unknown:{process_name.lower()}"
        extension = str(payload.get("file_extension") or Path(file_path).suffix.lower())
        size_raw = payload.get("file_size")
        return cls(
            event_id=str(payload.get("event_id") or ""),
            event_type=event_type,
            timestamp=parse_datetime(payload.get("timestamp")),
            file_path=file_path,
            file_extension=extension,
            file_size=int(size_raw) if size_raw not in (None, "") else None,
            thread_id=_optional_int(payload.get("thread_id")),
            process_id=process_id,
            process_name=process_name,
            process_path=_optional_str(payload.get("process_path")),
            process_start_time=process_start_time,
            process_key=process_key,
        )

    def to_dict(self, *, include_payloads: bool = True) -> dict[str, Any]:
        data = asdict(self)
        if not include_payloads:
            data.pop("features", None)
            data.pop("feature_vector", None)
        return _serialize(data)


@dataclass(slots=True)
class ProcessProfile:
    process_id: int | None
    process_name: str
    process_start_time: datetime | None
    process_key: str
    first_seen: datetime
    last_seen: datetime
    window_start: datetime
    window_size: int
    events_in_window: int = 0
    classified_events_count: int = 0
    benign_count: int = 0
    benign_encrypted_count: int = 0
    ransomware_encrypted_count: int = 0
    consecutive_ransomware_hits: int = 0
    ransomware_ratio: float = 0.0
    max_ransomware_probability: float = 0.0
    avg_ransomware_probability: float = 0.0
    touched_files: int = 0
    touched_files_unique: int = 0
    suspicion_score: int = 0
    threat_level: ThreatLevel = ThreatLevel.LOW
    decision_reason: str = ""
    last_event_id: str = ""
    profile_status: ProfileStatus = ProfileStatus.ACTIVE

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


def build_process_key(process_id: int, process_start_time: datetime) -> str:
    normalized = parse_datetime(process_start_time)
    return f"{int(process_id)}:{normalized.isoformat(timespec='microseconds')}"


def _optional_int(value: Any) -> int | None:
    return None if value in (None, "") else int(value)


def _optional_str(value: Any) -> str | None:
    return None if value in (None, "") else str(value)


def _serialize(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return parse_datetime(value).isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _serialize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_serialize(item) for item in value]
    return value
