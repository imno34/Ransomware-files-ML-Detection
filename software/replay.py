from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Iterable, Mapping

from .models import FileEvent


class ReplayFormatError(ValueError):
    pass


def load_replay_events(path: Path | str) -> list[FileEvent]:
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise ReplayFormatError(f"Replay file not found: {source}")
    try:
        if source.suffix.lower() == ".jsonl":
            payloads = [
                json.loads(line)
                for line in source.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        else:
            loaded = json.loads(source.read_text(encoding="utf-8"))
            payloads = loaded if isinstance(loaded, list) else [loaded]
    except (OSError, json.JSONDecodeError) as exc:
        raise ReplayFormatError(f"Cannot read replay events: {exc}") from exc
    events: list[FileEvent] = []
    for index, payload in enumerate(payloads, start=1):
        if not isinstance(payload, Mapping):
            raise ReplayFormatError(f"Replay item {index} must be an object")
        mutable: dict[str, Any] = dict(payload)
        if not mutable.get("event_id"):
            mutable["event_id"] = str(uuid.uuid4())
        try:
            events.append(FileEvent.from_mapping(mutable))
        except Exception as exc:
            raise ReplayFormatError(f"Invalid replay item {index}: {exc}") from exc
    return events
