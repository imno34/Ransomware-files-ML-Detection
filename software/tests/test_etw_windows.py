from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from software.config import MonitorConfig
from software.monitor import FileEventMonitor


@unittest.skipUnless(
    sys.platform == "win32" and os.environ.get("RUN_ETW_TESTS") == "1",
    "requires Windows, pywintrace, ETW privileges and RUN_ETW_TESTS=1",
)
class WindowsETWSmokeTest(unittest.TestCase):
    def test_file_change_reaches_callback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            received = []
            signal = threading.Event()

            def callback(event):
                received.append(event)
                signal.set()

            monitor = FileEventMonitor(
                MonitorConfig(monitored_directories=(root,)), callback
            )
            monitor.start()
            try:
                path = root / "etw-smoke.txt"
                path.write_text("first", encoding="utf-8")
                path.write_text("second", encoding="utf-8")
                signal.wait(timeout=10)
            finally:
                monitor.stop()
            self.assertTrue(received)
            self.assertEqual(Path(received[0].file_path).parent, root)
            self.assertIsNotNone(received[0].process_id)
            self.assertTrue(
                any(event.process_id == os.getpid() for event in received)
            )

    def test_existing_file_write_from_child_process_has_child_pid(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "existing.bin"
            path.write_bytes(b"A" * 131072)
            received = []
            signal = threading.Event()

            def callback(event):
                if (
                    Path(event.file_path) == path
                    and event.event_type.value == "modified"
                ):
                    received.append(event)
                    signal.set()

            monitor = FileEventMonitor(
                MonitorConfig(
                    monitored_directories=(root,),
                    directory_fallback_enabled=False,
                    system_logger_mode=True,
                ),
                callback,
            )
            monitor.start()
            try:
                child = subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        (
                            "from pathlib import Path; import sys, time; "
                            "p=Path(sys.argv[1]); "
                            "h=p.open('r+b'); h.write(b'B' * 32768); "
                            "h.flush(); h.close(); time.sleep(1)"
                        ),
                        str(path),
                    ]
                )
                child.wait(timeout=10)
                signal.wait(timeout=10)
            finally:
                monitor.stop()

            self.assertTrue(received)
            self.assertTrue(
                any(event.process_id == child.pid for event in received)
            )


if __name__ == "__main__":
    unittest.main()
