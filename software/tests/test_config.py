from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from software.config import ConfigurationError, RuntimeConfig


class RuntimeConfigTests(unittest.TestCase):
    def test_relative_paths_and_normalized_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "runtime.yaml"
            path.write_text(
                """
monitor:
  monitored_directories: [watched]
filters:
  trusted_processes: [C:/Windows/explorer.EXE]
  supported_extensions: [PDF]
storage:
  path: runtime/events.sqlite3
model:
  bundle_path: runtime/model.joblib
""",
                encoding="utf-8",
            )
            config = RuntimeConfig.load(path)
            self.assertEqual(
                config.monitor.monitored_directories, ((root / "watched").resolve(),)
            )
            self.assertIn("explorer.exe", config.filters.trusted_processes)
            self.assertIn(".pdf", config.filters.supported_extensions)
            self.assertEqual(
                config.storage.path, (root / "runtime/events.sqlite3").resolve()
            )
            self.assertTrue(config.monitor.etw_enabled)
            self.assertTrue(config.monitor.system_logger_mode)
            self.assertFalse(config.monitor.directory_fallback_enabled)

    def test_monitor_etw_modes_can_be_overridden(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "runtime.yaml"
            path.write_text(
                """
monitor:
  monitored_directories: [watched]
  etw_enabled: false
  system_logger_mode: false
  directory_fallback_enabled: true
storage:
  path: runtime.sqlite3
model:
  bundle_path: model.joblib
""",
                encoding="utf-8",
            )
            config = RuntimeConfig.load(path)
            self.assertFalse(config.monitor.etw_enabled)
            self.assertFalse(config.monitor.system_logger_mode)
            self.assertTrue(config.monitor.directory_fallback_enabled)

    def test_at_least_one_monitor_source_must_be_enabled(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "runtime.yaml"
            path.write_text(
                """
monitor:
  monitored_directories: [watched]
  etw_enabled: false
  directory_fallback_enabled: false
storage:
  path: runtime.sqlite3
model:
  bundle_path: model.joblib
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ConfigurationError, "At least one monitor source"
            ):
                RuntimeConfig.load(path)

    def test_stable_checks_cannot_exceed_attempts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "runtime.yaml"
            path.write_text(
                """
monitor:
  monitored_directories: [watched]
stabilization:
  stable_checks: 3
  max_attempts: 2
storage:
  path: runtime.sqlite3
model:
  bundle_path: model.joblib
""",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigurationError):
                RuntimeConfig.load(path)

    def test_runtime_outputs_inside_monitored_tree_must_be_ignored(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "runtime.yaml"
            path.write_text(
                """
monitor:
  monitored_directories: [watched]
storage:
  path: watched/runtime/events.sqlite3
model:
  bundle_path: model.joblib
logging:
  path: logs
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ConfigurationError, "recursive events"
            ):
                RuntimeConfig.load(path)

    def test_logging_path_must_be_a_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            log_file = root / "runtime.log"
            log_file.write_text("", encoding="utf-8")
            path = root / "runtime.yaml"
            path.write_text(
                f"""
monitor:
  monitored_directories: [watched]
storage:
  path: runtime.sqlite3
model:
  bundle_path: model.joblib
logging:
  path: {log_file.as_posix()}
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ConfigurationError, "must point to a directory"
            ):
                RuntimeConfig.load(path)


if __name__ == "__main__":
    unittest.main()
