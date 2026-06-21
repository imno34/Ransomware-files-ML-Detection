from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from software.replay import ReplayFormatError, load_replay_events


class ReplayTests(unittest.TestCase):
    def test_json_array_is_loaded(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.json"
            path.write_text(
                json.dumps(
                    [
                        {
                            "event_type": "modified",
                            "timestamp": "2026-06-18T10:00:00+00:00",
                            "file_path": str(Path(temp_dir) / "sample.bin"),
                            "process_id": 10,
                            "process_name": "sample.exe",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            events = load_replay_events(path)
            self.assertEqual(len(events), 1)
            self.assertTrue(events[0].event_id)
            self.assertEqual(events[0].process_key, "10:unknown")

    def test_invalid_item_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.json"
            path.write_text("[1]", encoding="utf-8")
            with self.assertRaises(ReplayFormatError):
                load_replay_events(path)


if __name__ == "__main__":
    unittest.main()
