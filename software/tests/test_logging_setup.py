from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from software.config import LoggingConfig
from software.logging_setup import (
    build_log_path,
    close_logging,
    configure_logging,
)


class LoggingSetupTests(unittest.TestCase):
    def tearDown(self):
        import logging

        close_logging(logging.getLogger("software"))

    def test_each_run_uses_timestamped_file_inside_configured_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir) / "logs"
            started_at = datetime(
                2026, 6, 20, 3, 39, 51, 603000, tzinfo=timezone.utc
            )
            logger = configure_logging(
                LoggingConfig(path=directory),
                started_at=started_at,
            )
            logger.info("test-message")
            close_logging(logger)

            expected = (
                directory
                / "ransomware-detection_2026-06-20_03-39-51_603000.log"
            )
            self.assertTrue(expected.is_file())
            content = expected.read_text(encoding="utf-8")
            self.assertIn("logging_started", content)
            self.assertIn("test-message", content)
            self.assertEqual(logger.handlers, [])

    def test_build_log_path_does_not_use_windows_forbidden_characters(self):
        path = build_log_path(
            Path("logs"),
            datetime(2026, 6, 20, 3, 39, 51, tzinfo=timezone.utc),
        )
        self.assertEqual(path.suffix, ".log")
        self.assertNotIn(":", path.name)


if __name__ == "__main__":
    unittest.main()
