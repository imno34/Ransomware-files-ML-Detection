from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from .models import EventType


class ConfigurationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class MonitorConfig:
    monitored_directories: tuple[Path, ...]
    ignored_directories: tuple[Path, ...] = ()
    etw_enabled: bool = True
    directory_fallback_enabled: bool = False
    system_logger_mode: bool = True
    allowed_event_types: tuple[EventType, ...] = (
        EventType.CREATED,
        EventType.MODIFIED,
        EventType.MOVED,
        EventType.DELETED,
    )
    dedup_window_ms: int = 500
    provider_name: str = "Microsoft-Windows-Kernel-File"
    provider_guid: str = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"
    provider_any_keywords: int = 0x1E90
    event_id_map: Mapping[int, EventType] = field(
        default_factory=lambda: {
            16: EventType.MODIFIED,
            26: EventType.DELETED,
            27: EventType.MOVED,
            30: EventType.CREATED,
        }
    )


@dataclass(frozen=True, slots=True)
class FilterConfig:
    trusted_processes: frozenset[str] = frozenset()
    supported_extensions: frozenset[str] = frozenset()
    ignored_extensions: frozenset[str] = frozenset(
        {".tmp", ".temp", ".swp", ".part", ".crdownload"}
    )
    temporary_name_prefixes: tuple[str, ...] = ("~$", "~", ".~")
    max_file_size_bytes: int = 100 * 1024 * 1024
    activity_window_seconds: int = 2
    high_activity_threshold: int = 10


@dataclass(frozen=True, slots=True)
class StabilizationConfig:
    interval_ms: int = 250
    stable_checks: int = 3
    max_attempts: int = 20


@dataclass(frozen=True, slots=True)
class ProcessingConfig:
    queue_size: int = 1024
    workers: int = 2
    extraction_fallback: bool = True


@dataclass(frozen=True, slots=True)
class ScoringConfig:
    window_seconds: int = 30


@dataclass(frozen=True, slots=True)
class StorageConfig:
    path: Path


@dataclass(frozen=True, slots=True)
class ModelConfig:
    bundle_path: Path


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    path: Path
    level: str = "INFO"
    max_bytes: int = 5 * 1024 * 1024
    backup_count: int = 3


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    source_path: Path
    monitor: MonitorConfig
    filters: FilterConfig
    stabilization: StabilizationConfig
    processing: ProcessingConfig
    scoring: ScoringConfig
    storage: StorageConfig
    model: ModelConfig
    logging: LoggingConfig

    @classmethod
    def load(cls, path: Path | str) -> "RuntimeConfig":
        source_path = Path(path).expanduser().resolve()
        if not source_path.is_file():
            raise ConfigurationError(f"Configuration file not found: {source_path}")
        with source_path.open("r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle) or {}
        if not isinstance(raw, Mapping):
            raise ConfigurationError("Configuration root must be a mapping")
        base_dir = source_path.parent

        monitor_raw = _mapping(raw, "monitor")
        monitored = tuple(
            _resolve_path(item, base_dir)
            for item in _required_list(monitor_raw, "monitored_directories")
        )
        ignored = tuple(
            _resolve_path(item, base_dir)
            for item in _list(monitor_raw, "ignored_directories", [])
        )
        allowed_types = tuple(
            EventType(str(value).lower())
            for value in _list(
                monitor_raw,
                "allowed_event_types",
                [
                    event.value
                    for event in MonitorConfig.__dataclass_fields__[
                        "allowed_event_types"
                    ].default
                ],
            )
        )
        id_map_raw = monitor_raw.get(
            "event_id_map",
            {
                16: "modified",
                26: "deleted",
                27: "moved",
                30: "created",
            },
        )
        if not isinstance(id_map_raw, Mapping):
            raise ConfigurationError("monitor.event_id_map must be a mapping")
        event_id_map = {
            int(key): EventType(str(value).lower())
            for key, value in id_map_raw.items()
        }

        filters_raw = _mapping(raw, "filters", required=False)
        stabilization_raw = _mapping(raw, "stabilization", required=False)
        processing_raw = _mapping(raw, "processing", required=False)
        scoring_raw = _mapping(raw, "scoring", required=False)
        storage_raw = _mapping(raw, "storage")
        model_raw = _mapping(raw, "model")
        logging_raw = _mapping(raw, "logging", required=False)

        config = cls(
            source_path=source_path,
            monitor=MonitorConfig(
                monitored_directories=monitored,
                ignored_directories=ignored,
                etw_enabled=bool(monitor_raw.get("etw_enabled", True)),
                directory_fallback_enabled=bool(
                    monitor_raw.get("directory_fallback_enabled", False)
                ),
                system_logger_mode=bool(
                    monitor_raw.get("system_logger_mode", True)
                ),
                allowed_event_types=allowed_types,
                dedup_window_ms=_positive_int(monitor_raw, "dedup_window_ms", 500),
                provider_name=str(
                    monitor_raw.get(
                        "provider_name", "Microsoft-Windows-Kernel-File"
                    )
                ),
                provider_guid=str(
                    monitor_raw.get(
                        "provider_guid",
                        "{EDD08927-9CC4-4E65-B970-C2560FB5C289}",
                    )
                ),
                provider_any_keywords=_integer(
                    monitor_raw, "provider_any_keywords", 0x1E90
                ),
                event_id_map=event_id_map,
            ),
            filters=FilterConfig(
                trusted_processes=frozenset(
                    _normalize_process_name(item)
                    for item in _list(filters_raw, "trusted_processes", [])
                ),
                supported_extensions=frozenset(
                    _normalize_extension(item)
                    for item in _list(filters_raw, "supported_extensions", [])
                ),
                ignored_extensions=frozenset(
                    _normalize_extension(item)
                    for item in _list(
                        filters_raw,
                        "ignored_extensions",
                        [".tmp", ".temp", ".swp", ".part", ".crdownload"],
                    )
                ),
                temporary_name_prefixes=tuple(
                    str(item).lower()
                    for item in _list(
                        filters_raw, "temporary_name_prefixes", ["~$", "~", ".~"]
                    )
                ),
                max_file_size_bytes=_positive_int(
                    filters_raw, "max_file_size_bytes", 100 * 1024 * 1024
                ),
                activity_window_seconds=_positive_int(
                    filters_raw, "activity_window_seconds", 2
                ),
                high_activity_threshold=_positive_int(
                    filters_raw, "high_activity_threshold", 10
                ),
            ),
            stabilization=StabilizationConfig(
                interval_ms=_positive_int(stabilization_raw, "interval_ms", 250),
                stable_checks=_positive_int(stabilization_raw, "stable_checks", 3),
                max_attempts=_positive_int(stabilization_raw, "max_attempts", 20),
            ),
            processing=ProcessingConfig(
                queue_size=_positive_int(processing_raw, "queue_size", 1024),
                workers=_positive_int(processing_raw, "workers", 2),
                extraction_fallback=bool(processing_raw.get("extraction_fallback", True)),
            ),
            scoring=ScoringConfig(
                window_seconds=_positive_int(scoring_raw, "window_seconds", 30)
            ),
            storage=StorageConfig(
                path=_resolve_path(_required(storage_raw, "path"), base_dir)
            ),
            model=ModelConfig(
                bundle_path=_resolve_path(_required(model_raw, "bundle_path"), base_dir)
            ),
            logging=LoggingConfig(
                path=_resolve_path(logging_raw.get("path", "logs"), base_dir),
                level=str(logging_raw.get("level", "INFO")).upper(),
                max_bytes=_positive_int(logging_raw, "max_bytes", 5 * 1024 * 1024),
                backup_count=_non_negative_int(logging_raw, "backup_count", 3),
            ),
        )
        config.validate()
        return config

    def validate(self) -> None:
        if not self.monitor.monitored_directories:
            raise ConfigurationError("monitor.monitored_directories cannot be empty")
        if (
            not self.monitor.etw_enabled
            and not self.monitor.directory_fallback_enabled
        ):
            raise ConfigurationError(
                "At least one monitor source must be enabled: "
                "monitor.etw_enabled or monitor.directory_fallback_enabled"
            )
        if self.stabilization.stable_checks > self.stabilization.max_attempts:
            raise ConfigurationError(
                "stabilization.stable_checks cannot exceed stabilization.max_attempts"
            )
        if self.logging.level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ConfigurationError(f"Unsupported logging level: {self.logging.level}")
        if self.logging.path.exists() and not self.logging.path.is_dir():
            raise ConfigurationError(
                "logging.path must point to a directory, not a file"
            )
        if not self.monitor.allowed_event_types:
            raise ConfigurationError("monitor.allowed_event_types cannot be empty")
        for output_path, label in (
            (self.storage.path, "storage.path"),
            (self.logging.path, "logging.path"),
        ):
            if any(
                _is_within(output_path, monitored)
                for monitored in self.monitor.monitored_directories
            ) and not any(
                _is_within(output_path, ignored)
                for ignored in self.monitor.ignored_directories
            ):
                raise ConfigurationError(
                    f"{label} is inside a monitored directory; add its parent "
                    "to monitor.ignored_directories to prevent recursive events"
                )


def _mapping(
    source: Mapping[str, Any], key: str, *, required: bool = True
) -> Mapping[str, Any]:
    value = source.get(key)
    if value is None and not required:
        return {}
    if not isinstance(value, Mapping):
        suffix = " is required" if value is None else " must be a mapping"
        raise ConfigurationError(f"{key}{suffix}")
    return value


def _required(source: Mapping[str, Any], key: str) -> Any:
    value = source.get(key)
    if value in (None, ""):
        raise ConfigurationError(f"Missing required configuration value: {key}")
    return value


def _list(source: Mapping[str, Any], key: str, default: list[Any]) -> list[Any]:
    value = source.get(key, default)
    if not isinstance(value, list):
        raise ConfigurationError(f"{key} must be a list")
    return value


def _required_list(source: Mapping[str, Any], key: str) -> list[Any]:
    value = _list(source, key, [])
    if not value:
        raise ConfigurationError(f"{key} cannot be empty")
    return value


def _positive_int(source: Mapping[str, Any], key: str, default: int) -> int:
    value = int(source.get(key, default))
    if value <= 0:
        raise ConfigurationError(f"{key} must be positive")
    return value


def _non_negative_int(source: Mapping[str, Any], key: str, default: int) -> int:
    value = int(source.get(key, default))
    if value < 0:
        raise ConfigurationError(f"{key} cannot be negative")
    return value


def _integer(source: Mapping[str, Any], key: str, default: int) -> int:
    raw = source.get(key, default)
    value = int(raw, 0) if isinstance(raw, str) else int(raw)
    if value < 0:
        raise ConfigurationError(f"{key} cannot be negative")
    return value


def _resolve_path(value: Any, base_dir: Path) -> Path:
    path = Path(str(value)).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def _normalize_extension(value: Any) -> str:
    normalized = str(value).strip().lower()
    if normalized and not normalized.startswith("."):
        normalized = f".{normalized}"
    return normalized


def _normalize_process_name(value: Any) -> str:
    return Path(str(value).strip()).name.lower()


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except (ValueError, OSError):
        return False
