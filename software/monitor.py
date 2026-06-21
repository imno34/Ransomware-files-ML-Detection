from __future__ import annotations

import ctypes as ct
import importlib
import logging
import struct
import sys
import threading
import uuid
from collections import Counter
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Mapping

import psutil

from .config import MonitorConfig
from .directory_monitor import WindowsDirectoryMonitor
from .models import (
    EventType,
    FileEvent,
    build_process_key,
    parse_datetime,
    utc_now,
)


class ETWUnavailableError(RuntimeError):
    pass


class EventDeduplicator:
    def __init__(self, window_ms: int):
        self.window = timedelta(milliseconds=window_ms)
        self._last_seen: dict[tuple[str, str, str], Any] = {}
        self._lock = RLock()

    def is_duplicate(self, event: FileEvent) -> bool:
        key = (
            event.process_key,
            _path_key(event.file_path),
            event.event_type.value,
        )
        with self._lock:
            previous = self._last_seen.get(key)
            self._last_seen[key] = event.timestamp
            cutoff = event.timestamp - self.window * 4
            stale = [
                existing_key
                for existing_key, timestamp in self._last_seen.items()
                if timestamp < cutoff
            ]
            for existing_key in stale:
                self._last_seen.pop(existing_key, None)
        if previous is None:
            return False
        delta = event.timestamp - previous
        return timedelta(0) <= delta <= self.window


class FileEventMonitor:
    _NAME_CREATE_EVENT_ID = 10
    _NAME_DELETE_EVENT_ID = 11
    _FILE_CREATE_CORRELATION_EVENT_ID = 12
    _CORRELATION_EVENT_IDS = frozenset(
        {
            _NAME_CREATE_EVENT_ID,
            _NAME_DELETE_EVENT_ID,
            _FILE_CREATE_CORRELATION_EVENT_ID,
        }
    )

    def __init__(
        self,
        config: MonitorConfig,
        callback: Callable[[FileEvent], None],
        *,
        logger: logging.Logger | None = None,
    ):
        self.config = config
        self.callback = callback
        self.logger = logger or logging.getLogger("software.monitor")
        self.deduplicator = EventDeduplicator(config.dedup_window_ms)
        self._job: Any = None
        self._file_names: dict[str, str] = {}
        self._file_names_lock = RLock()
        self._process_metadata_cache: dict[
            int, tuple[str, str | None, Any | None]
        ] = {}
        self._directory_monitor: WindowsDirectoryMonitor | None = None
        self._etw_raw_event_count = 0
        self._etw_normalized_event_count = 0
        self._delivered_event_count = 0
        self._deduplicated_event_count = 0
        self._etw_internal_event_count = 0
        self._etw_rejected: Counter[str] = Counter()

    def start(self) -> None:
        if sys.platform != "win32":
            raise ETWUnavailableError("File monitoring is available only on Windows")
        if not self.config.etw_enabled:
            if not self.config.directory_fallback_enabled:
                raise ETWUnavailableError(
                    "No file monitoring source is enabled"
                )
            self._start_directory_fallback()
            self.logger.info(
                "File monitor started source=ReadDirectoryChangesW "
                "directories=%s process_metadata=unavailable",
                [str(path) for path in self.config.monitored_directories],
            )
            return
        try:
            import etw
        except ImportError as exc:
            raise ETWUnavailableError(
                "pywintrace is not installed; install software/requirements.txt"
            ) from exc
        etw_impl = importlib.import_module("etw.etw")
        trace_properties = _build_trace_properties(
            etw_impl,
            system_logger_mode=self.config.system_logger_mode,
        )
        provider = etw.ProviderInfo(
            self.config.provider_name,
            etw.GUID(self.config.provider_guid),
            any_keywords=self.config.provider_any_keywords,
        )
        self._job = etw.ETW(
            session_name=f"RansomwareDetection-{uuid.uuid4()}",
            properties=trace_properties,
            providers=[provider],
            event_callback=self._on_raw_event,
            event_id_filters=sorted(
                {
                    *self.config.event_id_map,
                    *self._CORRELATION_EVENT_IDS,
                }
            ),
        )
        self._start_with_safe_consumer(self._job)
        if self.config.directory_fallback_enabled:
            self._start_directory_fallback()
        self.logger.info(
            "ETW monitor started provider=%s directories=%s keywords=%#x "
            "event_ids=%s system_logger_mode=%s session=%s",
            self.config.provider_name,
            [str(path) for path in self.config.monitored_directories],
            self.config.provider_any_keywords,
            sorted(
                {
                    *self.config.event_id_map,
                    *self._CORRELATION_EVENT_IDS,
                }
            ),
            self.config.system_logger_mode,
            self._job.session_name,
        )

    def _start_directory_fallback(self) -> None:
        self._directory_monitor = WindowsDirectoryMonitor(
            self.config.monitored_directories,
            self._emit_event,
            logger=self.logger,
        )
        self._directory_monitor.start()

    def stop(self) -> None:
        if self._directory_monitor is not None:
            self._directory_monitor.stop()
            self._directory_monitor = None
        job = self._job
        if job is None:
            return
        self._job = None
        errors: list[str] = []
        job.running = False

        # pywintrace stops the provider first. On some Windows builds this
        # leaves ProcessTrace blocked and Ctrl+C never completes.
        consumer = getattr(job, "consumer", None)
        if consumer is not None:
            try:
                consumer.stop()
            except Exception as exc:
                errors.append(f"consumer: {type(exc).__name__}: {exc}")

        provider = getattr(job, "provider", None)
        if provider is not None:
            try:
                provider.stop()
            except Exception as exc:
                errors.append(f"provider: {type(exc).__name__}: {exc}")

        if errors:
            self.logger.warning(
                "ETW monitor stopped with cleanup errors: %s", "; ".join(errors)
            )
        else:
            self.logger.info(
                "ETW monitor stopped raw_events=%s internal_events=%s "
                "normalized_events=%s delivered_events=%s deduplicated_events=%s "
                "rejected=%s",
                self._etw_raw_event_count,
                self._etw_internal_event_count,
                self._etw_normalized_event_count,
                self._delivered_event_count,
                self._deduplicated_event_count,
                dict(self._etw_rejected),
            )

    def _on_raw_event(self, *args: Any, **kwargs: Any) -> None:
        try:
            raw = _merge_callback_payload(args, kwargs)
            self._etw_raw_event_count += 1
            if self._etw_raw_event_count == 1:
                flattened = _flatten_mapping(raw)
                self.logger.info(
                    "ETW first raw event id=%s pid=%s tid=%s task=%s",
                    _raw_event_id(flattened),
                    _first(flattened, "processid", "pid", "process_id"),
                    _first(flattened, "threadid", "tid", "thread_id"),
                    _first(
                        flattened,
                        "taskname",
                        "eventname",
                        "operation",
                    ),
                )
            event = self.consume_raw_event(raw)
            if event is not None:
                self._etw_normalized_event_count += 1
                self._emit_event(event)
        except Exception:
            self.logger.exception("Failed to normalize ETW event")

    def _emit_event(self, event: FileEvent) -> None:
        if self.deduplicator.is_duplicate(event):
            self._deduplicated_event_count += 1
            return
        self._delivered_event_count += 1
        self.callback(event)

    def consume_raw_event(self, raw: Mapping[str, Any]) -> FileEvent | None:
        normalized = _flatten_mapping(raw)
        self._cache_process_metadata(normalized)
        event_id = _raw_event_id(normalized)
        if event_id == self._NAME_DELETE_EVENT_ID:
            self._etw_internal_event_count += 1
            self._forget_file_name(normalized)
            return None
        # Create events contain both FileObject and FileName. Remembering this
        # pair is essential because subsequent Write/SetInformation events
        # often contain only FileObject.
        self._remember_file_name(normalized)
        if event_id in {
            self._NAME_CREATE_EVENT_ID,
            self._FILE_CREATE_CORRELATION_EVENT_ID,
        }:
            self._etw_internal_event_count += 1
            return None
        return self._normalize_flattened_event(normalized)

    def normalize_event(self, raw: Mapping[str, Any]) -> FileEvent | None:
        return self._normalize_flattened_event(_flatten_mapping(raw))

    def _normalize_flattened_event(
        self, normalized: Mapping[str, Any]
    ) -> FileEvent | None:
        event_type = self._event_type(normalized)
        if event_type is None or event_type not in self.config.allowed_event_types:
            self._etw_rejected["unsupported_event_type"] += 1
            return None
        file_path = _first(
            normalized,
            "filename",
            "filepath",
            "openpath",
            "targetfilename",
            "newname",
            "path",
        )
        if not file_path:
            file_path = self._lookup_file_name(normalized)
        if not file_path:
            self._etw_rejected["unresolved_path"] += 1
            return None
        path = Path(_normalize_windows_file_path(str(file_path)))
        if not self._is_monitored(path):
            self._etw_rejected["outside_monitored_directories"] += 1
            return None
        if self._is_ignored(path):
            self._etw_rejected["ignored_directory"] += 1
            return None
        try:
            if path.exists() and path.is_dir():
                self._etw_rejected["directory_event"] += 1
                return None
        except OSError:
            pass

        process_id = _optional_int(
            _first(normalized, "processid", "pid", "process_id")
        )
        thread_id = _optional_int(
            _first(normalized, "threadid", "tid", "thread_id")
        )
        process_name, process_path, process_start_time = (
            self._resolve_process_metadata(process_id)
        )
        if process_id is not None and process_start_time is not None:
            process_key = build_process_key(process_id, process_start_time)
        elif process_id is not None:
            process_key = f"{process_id}:unknown"
        else:
            process_key = f"unknown:{process_name.lower()}"
        file_size = None
        try:
            if path.is_file():
                file_size = path.stat().st_size
        except OSError:
            pass
        return FileEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            timestamp=parse_datetime(
                _first(normalized, "timestamp", "timecreated", "eventtime"),
                default=utc_now(),
            ),
            file_path=str(path),
            file_extension=path.suffix.lower(),
            file_size=file_size,
            thread_id=thread_id,
            process_id=process_id,
            process_name=process_name,
            process_path=process_path,
            process_start_time=process_start_time,
            process_key=process_key,
        )

    def _remember_file_name(self, raw: Mapping[str, Any]) -> None:
        file_path = _first(
            raw,
            "filename",
            "filepath",
            "openpath",
            "targetfilename",
            "newname",
            "path",
        )
        if not file_path:
            return
        identifiers = _file_identifiers(raw)
        if not identifiers:
            return
        normalized_path = _normalize_windows_file_path(str(file_path))
        path = Path(normalized_path)
        if not self._is_monitored(path) or self._is_ignored(path):
            return
        with self._file_names_lock:
            for identifier in identifiers:
                self._file_names[identifier] = normalized_path

    def _forget_file_name(self, raw: Mapping[str, Any]) -> None:
        with self._file_names_lock:
            for identifier in _file_identifiers(raw):
                self._file_names.pop(identifier, None)

    def _lookup_file_name(self, raw: Mapping[str, Any]) -> str | None:
        with self._file_names_lock:
            for identifier in _file_identifiers(raw):
                file_path = self._file_names.get(identifier)
                if file_path:
                    return file_path
        return None

    def _cache_process_metadata(self, raw: Mapping[str, Any]) -> None:
        process_id = _optional_int(
            _first(raw, "processid", "pid", "process_id")
        )
        if process_id is None or process_id in self._process_metadata_cache:
            return
        metadata = _process_metadata(process_id)
        if len(self._process_metadata_cache) >= 4096:
            oldest_process_id = next(iter(self._process_metadata_cache))
            self._process_metadata_cache.pop(oldest_process_id, None)
        self._process_metadata_cache[process_id] = metadata

    def _resolve_process_metadata(
        self,
        process_id: int | None,
    ) -> tuple[str, str | None, Any | None]:
        if process_id is None:
            return "unknown", None, None
        cached = self._process_metadata_cache.get(process_id)
        if cached is not None:
            return cached
        metadata = _process_metadata(process_id)
        self._process_metadata_cache[process_id] = metadata
        return metadata

    @staticmethod
    def _start_with_safe_consumer(job: Any) -> None:
        etw_impl = importlib.import_module("etw.etw")
        base_consumer = etw_impl.EventConsumer

        class SafeEventConsumer(base_consumer):
            def start(self) -> None:
                self.trace_handle = etw_impl.et.OpenTraceW(
                    ct.byref(self.trace_logfile)
                )
                if self.trace_handle == etw_impl.et.INVALID_PROCESSTRACE_HANDLE:
                    raise ct.WinError()
                self.trace_handle = etw_impl.et.TRACEHANDLE(self.trace_handle)
                self.process_thread = threading.Thread(
                    target=self._run,
                    args=(self.trace_handle, self.end_capture),
                    name="ransomware-etw-consumer",
                    daemon=True,
                )
                self.process_thread.start()

            def stop(self) -> None:
                self.end_capture.set()
                if self.trace_handle is not None:
                    etw_impl.et.CloseTrace(self.trace_handle)
                if self.process_thread is not None:
                    self.process_thread.join(timeout=3.0)

            def _processEvent(self, record: Any) -> None:
                fast_event = _parse_kernel_file_event_record(record)
                if fast_event is None:
                    super()._processEvent(record)
                    return
                event_id, payload = fast_event
                if self.event_id_filters and event_id not in self.event_id_filters:
                    return
                if self.event_callback is not None:
                    self.event_callback((event_id, payload))

        original_consumer = etw_impl.EventConsumer
        etw_impl.EventConsumer = SafeEventConsumer
        try:
            job.start()
        finally:
            etw_impl.EventConsumer = original_consumer

    def _event_type(self, raw: Mapping[str, Any]) -> EventType | None:
        event_name = str(
            _first(raw, "eventname", "taskname", "opcode", "operation") or ""
        ).lower()
        if "delete" in event_name:
            return EventType.DELETED
        if "rename" in event_name or "move" in event_name:
            return EventType.MOVED
        if "write" in event_name or "modify" in event_name:
            return EventType.MODIFIED
        if "create" in event_name:
            return EventType.CREATED
        event_id = _optional_int(_first(raw, "eventid", "id", "event_id"))
        return self.config.event_id_map.get(event_id) if event_id is not None else None

    def _is_monitored(self, path: Path) -> bool:
        return any(
            _is_relative_to(path, root)
            for root in self.config.monitored_directories
        )

    def _is_ignored(self, path: Path) -> bool:
        return any(
            _is_relative_to(path, root)
            for root in self.config.ignored_directories
        )


def _merge_callback_payload(
    args: tuple[Any, ...], kwargs: Mapping[str, Any]
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if (
        len(args) == 1
        and isinstance(args[0], tuple)
        and len(args[0]) == 2
        and isinstance(args[0][1], Mapping)
    ):
        payload.update(args[0][1])
        payload.setdefault("event_id", args[0][0])
    elif len(args) == 1 and isinstance(args[0], Mapping):
        payload.update(args[0])
    elif len(args) >= 2 and isinstance(args[-1], Mapping):
        payload.update(args[-1])
        payload.setdefault("event_id", args[0])
    else:
        for item in args:
            if isinstance(item, Mapping):
                payload.update(item)
    payload.update(kwargs)
    return payload


def _build_trace_properties(
    etw_impl: Any,
    *,
    system_logger_mode: bool,
) -> Any | None:
    if not system_logger_mode:
        return None
    properties = etw_impl.TraceProperties()
    properties.get().contents.LogFileMode |= (
        etw_impl.et.EVENT_TRACE_SYSTEM_LOGGER_MODE
    )
    return properties


_FAST_KERNEL_FILE_TASKS = {
    10: "NAMECREATE",
    11: "NAMEDELETE",
    12: "CREATE",
    16: "WRITE",
}


def _parse_kernel_file_event_record(
    record: Any,
) -> tuple[int, dict[str, Any]] | None:
    header = record.contents.EventHeader
    event_id = int(header.EventDescriptor.Id)
    if event_id not in _FAST_KERNEL_FILE_TASKS:
        return None
    data_length = int(record.contents.UserDataLength)
    data = (
        ct.string_at(record.contents.UserData, data_length)
        if data_length > 0 and record.contents.UserData
        else b""
    )
    parsed = _decode_kernel_file_payload(event_id, data)
    if parsed is None:
        return None
    payload: dict[str, Any] = {
        "EventHeader": {
            "Size": header.Size,
            "HeaderType": header.HeaderType,
            "Flags": header.Flags,
            "EventProperty": header.EventProperty,
            "ThreadId": header.ThreadId,
            "ProcessId": header.ProcessId,
            "TimeStamp": header.TimeStamp,
            "ProviderId": str(header.ProviderId),
            "EventDescriptor": {
                "Id": event_id,
                "Version": header.EventDescriptor.Version,
                "Channel": header.EventDescriptor.Channel,
                "Level": header.EventDescriptor.Level,
                "Opcode": header.EventDescriptor.Opcode,
                "Task": header.EventDescriptor.Task,
                "Keyword": header.EventDescriptor.Keyword,
            },
            "ActivityId": str(header.ActivityId),
        },
        "Task Name": _FAST_KERNEL_FILE_TASKS[event_id],
    }
    payload.update(parsed)
    return event_id, payload


def _decode_kernel_file_payload(
    event_id: int,
    data: bytes,
) -> dict[str, Any] | None:
    try:
        if event_id in {10, 11}:
            if len(data) < 8:
                return None
            (file_key,) = struct.unpack_from("<Q", data, 0)
            return {
                "FileKey": _pointer_text(file_key),
                "FileName": _decode_utf16z(data[8:]),
            }
        if event_id == 12:
            if len(data) < 32:
                return None
            (
                irp,
                file_object,
                issuing_thread_id,
                create_options,
                create_attributes,
                share_access,
            ) = struct.unpack_from("<QQIIII", data, 0)
            return {
                "Irp": _pointer_text(irp),
                "FileObject": _pointer_text(file_object),
                "IssuingThreadId": issuing_thread_id,
                "CreateOptions": create_options,
                "CreateAttributes": create_attributes,
                "ShareAccess": share_access,
                "FileName": _decode_utf16z(data[32:]),
            }
        if event_id == 16:
            if len(data) < 48:
                return None
            (
                byte_offset,
                irp,
                file_object,
                file_key,
                issuing_thread_id,
                io_size,
                io_flags,
                extra_flags,
            ) = struct.unpack_from("<QQQQIIII", data, 0)
            return {
                "ByteOffset": byte_offset,
                "Irp": _pointer_text(irp),
                "FileObject": _pointer_text(file_object),
                "FileKey": _pointer_text(file_key),
                "IssuingThreadId": issuing_thread_id,
                "IOSize": io_size,
                "IOFlags": io_flags,
                "ExtraFlags": extra_flags,
            }
    except (struct.error, UnicodeDecodeError):
        return None
    return None


def _pointer_text(value: int) -> str:
    return f"0x{int(value):X}"


def _decode_utf16z(value: bytes) -> str:
    if not value:
        return ""
    decoded = value.decode("utf-16-le")
    return decoded.split("\x00", 1)[0]


def _flatten_mapping(source: Mapping[str, Any]) -> dict[str, Any]:
    flattened: dict[str, Any] = {}

    def visit(mapping: Mapping[str, Any]) -> None:
        for key, value in mapping.items():
            normalized_key = _normalized_key(key)
            if isinstance(value, Mapping):
                visit(value)
            elif normalized_key not in flattened or flattened[normalized_key] in (None, ""):
                flattened[normalized_key] = value

    visit(source)
    return flattened


def _process_metadata(
    process_id: int | None,
) -> tuple[str, str | None, Any | None]:
    if process_id is None:
        return "unknown", None, None
    try:
        process = psutil.Process(process_id)
        name = process.name() or "unknown"
        try:
            executable = process.exe() or None
        except (psutil.AccessDenied, psutil.ZombieProcess):
            executable = None
        start_time = parse_datetime(process.create_time())
        return name, executable, start_time
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
        return "unknown", None, None


def _first(source: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        value = source.get(key)
        if value not in (None, ""):
            return value
    return None


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _raw_event_id(source: Mapping[str, Any]) -> int | None:
    return _optional_int(_first(source, "event_id", "eventid", "id"))


def _file_identifiers(source: Mapping[str, Any]) -> tuple[str, ...]:
    identifiers: list[str] = []
    for key in (
        "filekey",
        "fileobject",
        "fileid",
        "key",
        "file_object",
        "file_key",
    ):
        value = source.get(key)
        if value not in (None, "", 0, "0", "0x0"):
            identifier = str(value).strip().lower()
            if identifier not in identifiers:
                identifiers.append(identifier)
    return tuple(identifiers)


def _normalized_key(value: Any) -> str:
    return "".join(
        character
        for character in str(value).lower()
        if character.isalnum() or character == "_"
    )


def _path_key(value: str) -> str:
    return str(Path(value).resolve(strict=False)).casefold()


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        candidate = path.expanduser().resolve(strict=False)
        base = root.expanduser().resolve(strict=False)
        candidate.relative_to(base)
        return True
    except (ValueError, OSError):
        return False


def _normalize_windows_file_path(value: str) -> str:
    if sys.platform != "win32":
        return value
    if value.startswith("\\\\?\\"):
        return value[4:]
    if value.startswith("\\??\\"):
        return value[4:]
    if value.lower().startswith("\\device\\mup\\"):
        return "\\\\" + value[len("\\Device\\Mup\\") :]
    folded = value.casefold()
    for device_prefix, drive in _device_drive_map():
        if folded.startswith(device_prefix.casefold()):
            return drive + value[len(device_prefix) :]
    return value


@lru_cache(maxsize=1)
def _device_drive_map() -> tuple[tuple[str, str], ...]:
    if sys.platform != "win32":
        return ()
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        buffer = ctypes.create_unicode_buffer(1024)
        mappings: list[tuple[str, str]] = []
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            drive = f"{letter}:"
            result = kernel32.QueryDosDeviceW(drive, buffer, len(buffer))
            if result:
                target = buffer.value
                if target:
                    mappings.append((target, drive))
        mappings.sort(key=lambda item: len(item[0]), reverse=True)
        return tuple(mappings)
    except (AttributeError, OSError):
        return ()
