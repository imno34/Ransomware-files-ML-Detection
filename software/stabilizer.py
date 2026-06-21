from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable

from .config import StabilizationConfig
from .models import FileEvent, StabilizationStatus


SleepCallable = Callable[[float], Awaitable[None]]


class FileStabilizer:
    def __init__(
        self,
        config: StabilizationConfig,
        *,
        sleep: SleepCallable = asyncio.sleep,
    ):
        self.config = config
        self._sleep = sleep

    async def stabilize(self, event: FileEvent) -> FileEvent:
        path = Path(event.file_path)
        last_signature: tuple[int, int] | None = None
        equal_checks = 0
        last_error: str | None = None

        for attempt in range(1, self.config.max_attempts + 1):
            event.stabilization_attempts = attempt
            try:
                stat_result = path.stat()
                if not path.is_file():
                    raise OSError("path is not a regular file")
                with path.open("rb") as handle:
                    handle.read(1)
                signature = (int(stat_result.st_size), int(stat_result.st_mtime_ns))
                if signature == last_signature:
                    equal_checks += 1
                else:
                    last_signature = signature
                    equal_checks = 1
                if equal_checks >= self.config.stable_checks:
                    event.stabilization_status = StabilizationStatus.STABLE
                    event.stable_file_size = signature[0]
                    event.file_size = signature[0]
                    event.stable_mtime = datetime.fromtimestamp(
                        stat_result.st_mtime, tz=timezone.utc
                    )
                    event.stabilization_error = None
                    return event
                last_error = None
            except OSError as exc:
                last_signature = None
                equal_checks = 0
                last_error = f"{type(exc).__name__}: {exc}"

            if attempt < self.config.max_attempts:
                await self._sleep(self.config.interval_ms / 1000.0)

        event.stabilization_status = StabilizationStatus.FAILED
        event.stabilization_error = last_error or "file remained unstable"
        return event
