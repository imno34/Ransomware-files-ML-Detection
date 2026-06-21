from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from software.config import StabilizationConfig
from software.models import StabilizationStatus
from software.stabilizer import FileStabilizer
from software.tests.helpers import make_event


async def no_sleep(_seconds: float) -> None:
    return None


class FileStabilizerTests(unittest.IsolatedAsyncioTestCase):
    async def test_stable_after_required_checks(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.bin"
            path.write_bytes(b"stable")
            event = make_event(path)
            stabilizer = FileStabilizer(
                StabilizationConfig(
                    interval_ms=1, stable_checks=3, max_attempts=4
                ),
                sleep=no_sleep,
            )
            await stabilizer.stabilize(event)
            self.assertEqual(
                event.stabilization_status, StabilizationStatus.STABLE
            )
            self.assertEqual(event.stabilization_attempts, 3)
            self.assertEqual(event.stable_file_size, 6)

    async def test_missing_file_fails(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            event = make_event(Path(temp_dir) / "missing.bin")
            stabilizer = FileStabilizer(
                StabilizationConfig(
                    interval_ms=1, stable_checks=2, max_attempts=2
                ),
                sleep=no_sleep,
            )
            await stabilizer.stabilize(event)
            self.assertEqual(
                event.stabilization_status, StabilizationStatus.FAILED
            )
            self.assertIn("FileNotFoundError", event.stabilization_error)


if __name__ == "__main__":
    unittest.main()
