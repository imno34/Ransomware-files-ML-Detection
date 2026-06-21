from __future__ import annotations

import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .config import LoggingConfig


LOG_FILE_PREFIX = "ransomware-detection"
LOG_TIMESTAMP_FORMAT = "%Y-%m-%d_%H-%M-%S_%f"


def configure_logging(
    config: LoggingConfig,
    *,
    started_at: datetime | None = None,
) -> logging.Logger:
    """Configure one timestamped log file for the current application run."""
    started_at = started_at or datetime.now().astimezone()
    log_directory = config.path
    log_directory.mkdir(parents=True, exist_ok=True)
    log_path = build_log_path(log_directory, started_at)

    logger = logging.getLogger("software")
    logger.setLevel(getattr(logging, config.level))
    logger.propagate = False
    if logger.handlers:
        close_logging(logger)

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s"
    )
    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=config.max_bytes,
        backupCount=config.backup_count,
        encoding="utf-8",
    )
    file_handler.namer = _rotation_file_name
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    logger.info(
        "logging_started started_at=%s file=%s",
        started_at.isoformat(),
        log_path,
    )
    return logger


def close_logging(logger: logging.Logger) -> None:
    """Flush, close and detach all handlers owned by the runtime logger."""
    for handler in list(logger.handlers):
        try:
            handler.flush()
        finally:
            handler.close()
            logger.removeHandler(handler)


def build_log_path(log_directory: Path, started_at: datetime) -> Path:
    timestamp = started_at.strftime(LOG_TIMESTAMP_FORMAT)
    return log_directory / f"{LOG_FILE_PREFIX}_{timestamp}.log"


def _rotation_file_name(default_name: str) -> str:
    """Keep rotated parts as .log files instead of the default .log.1."""
    default_path = Path(default_name)
    part_number = default_path.suffix.lstrip(".")
    base_path = default_path.with_suffix("")
    return str(
        base_path.with_name(f"{base_path.stem}_part-{part_number}.log")
    )
