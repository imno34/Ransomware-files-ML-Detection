from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path

from .config import FilterConfig, MonitorConfig
from .models import EventPriority, EventType, FileEvent, FilterDecision


class EventPreFilter:
    def __init__(self, config: FilterConfig, monitor_config: MonitorConfig):
        self.config = config
        self.monitor_config = monitor_config
        self._activity: dict[str, deque] = defaultdict(deque)

    def filter(self, event: FileEvent) -> FileEvent:
        priority_reasons: list[str] = []
        path = Path(event.file_path)
        extension = (event.file_extension or path.suffix).lower()
        event.file_extension = extension

        if event.event_type == EventType.DELETED:
            event.filter_decision = FilterDecision.CONTEXT_ONLY
            event.filter_reason = "delete_event"
            event.event_priority = self._assign_priority(event, priority_reasons)
            return event

        if self._inside_ignored_directory(path):
            event.filter_decision = FilterDecision.DROP
            event.filter_reason = "ignored_directory"
            event.event_priority = EventPriority.LOW
            return event

        if self._is_temporary(path, extension):
            event.filter_decision = FilterDecision.DROP
            event.filter_reason = "temporary_or_service_file"
            event.event_priority = EventPriority.LOW
            return event

        if Path(event.process_name).name.lower() in self.config.trusted_processes:
            event.filter_decision = FilterDecision.DROP
            event.filter_reason = "trusted_process"
            event.event_priority = EventPriority.LOW
            return event

        size = event.file_size
        if size is None:
            try:
                size = path.stat().st_size
                event.file_size = size
            except OSError:
                size = None
        if size is not None and size > self.config.max_file_size_bytes:
            event.filter_decision = FilterDecision.CONTEXT_ONLY
            event.filter_reason = "file_too_large"
            event.event_priority = EventPriority.LOW
            return event

        event.filter_decision = FilterDecision.PASS
        event.filter_reason = "accepted"
        event.event_priority = self._assign_priority(event, priority_reasons)
        if priority_reasons:
            event.filter_reason = f"accepted; priority={','.join(priority_reasons)}"
        return event

    def _assign_priority(
        self, event: FileEvent, priority_reasons: list[str]
    ) -> EventPriority:
        if event.process_id is None or event.process_name.lower() == "unknown":
            priority_reasons.append("unknown_process")
        if (
            self.config.supported_extensions
            and event.file_extension.lower() not in self.config.supported_extensions
        ):
            priority_reasons.append("unusual_extension")
        if self._record_activity(event):
            priority_reasons.append("high_activity")
        return EventPriority.HIGH if priority_reasons else EventPriority.NORMAL

    def _record_activity(self, event: FileEvent) -> bool:
        queue = self._activity[event.process_key]
        cutoff = event.timestamp - timedelta(
            seconds=self.config.activity_window_seconds
        )
        while queue and queue[0] < cutoff:
            queue.popleft()
        queue.append(event.timestamp)
        return len(queue) >= self.config.high_activity_threshold

    def _inside_ignored_directory(self, path: Path) -> bool:
        candidate = _resolved_without_requirement(path)
        for ignored in self.monitor_config.ignored_directories:
            try:
                candidate.relative_to(ignored)
                return True
            except ValueError:
                continue
        return False

    def _is_temporary(self, path: Path, extension: str) -> bool:
        lowered_name = path.name.lower()
        if extension in self.config.ignored_extensions:
            return True
        return any(
            lowered_name.startswith(prefix)
            for prefix in self.config.temporary_name_prefixes
        )


def _resolved_without_requirement(path: Path) -> Path:
    try:
        return path.expanduser().resolve(strict=False)
    except OSError:
        return Path(str(path)).absolute()
