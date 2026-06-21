from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from software.config import FilterConfig, MonitorConfig
from software.filtering import EventPreFilter
from software.models import (
    EventPriority,
    EventType,
    FilterDecision,
)
from software.monitor import EventDeduplicator
from software.tests.helpers import make_event


class EventPreFilterTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.config = FilterConfig(
            trusted_processes=frozenset({"trusted.exe"}),
            supported_extensions=frozenset({".txt"}),
            max_file_size_bytes=4,
            activity_window_seconds=2,
            high_activity_threshold=2,
        )
        self.monitor = MonitorConfig(monitored_directories=(self.root,))
        self.prefilter = EventPreFilter(self.config, self.monitor)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_delete_is_context_only(self):
        event = make_event(
            self.root / "gone.txt", event_type=EventType.DELETED
        )
        self.prefilter.filter(event)
        self.assertEqual(event.filter_decision, FilterDecision.CONTEXT_ONLY)

    def test_temporary_file_is_dropped(self):
        path = self.root / "sample.tmp"
        path.write_bytes(b"x")
        event = make_event(path)
        self.prefilter.filter(event)
        self.assertEqual(event.filter_decision, FilterDecision.DROP)
        self.assertEqual(event.filter_reason, "temporary_or_service_file")

    def test_trusted_process_is_dropped(self):
        path = self.root / "sample.txt"
        path.write_bytes(b"x")
        event = make_event(path, process_name="TRUSTED.EXE")
        self.prefilter.filter(event)
        self.assertEqual(event.filter_decision, FilterDecision.DROP)

    def test_large_file_is_context_only(self):
        path = self.root / "large.txt"
        path.write_bytes(b"12345")
        event = make_event(path)
        self.prefilter.filter(event)
        self.assertEqual(event.filter_decision, FilterDecision.CONTEXT_ONLY)

    def test_unknown_extension_and_activity_raise_priority(self):
        first_path = self.root / "first.bin"
        second_path = self.root / "second.bin"
        first_path.write_bytes(b"x")
        second_path.write_bytes(b"x")
        first = make_event(first_path)
        second = make_event(
            second_path,
            event_id="event-2",
            timestamp=first.timestamp + timedelta(milliseconds=100),
        )
        self.prefilter.filter(first)
        self.prefilter.filter(second)
        self.assertEqual(first.event_priority, EventPriority.HIGH)
        self.assertEqual(second.event_priority, EventPriority.HIGH)
        self.assertIn("high_activity", second.filter_reason)


class DeduplicationTests(unittest.TestCase):
    def test_events_inside_window_are_duplicates(self):
        root = Path(tempfile.gettempdir())
        first = make_event(root / "same.txt")
        second = make_event(
            root / "same.txt",
            event_id="event-2",
            timestamp=first.timestamp + timedelta(milliseconds=400),
        )
        third = make_event(
            root / "same.txt",
            event_id="event-3",
            timestamp=first.timestamp + timedelta(milliseconds=1100),
        )
        deduplicator = EventDeduplicator(500)
        self.assertFalse(deduplicator.is_duplicate(first))
        self.assertTrue(deduplicator.is_duplicate(second))
        self.assertFalse(deduplicator.is_duplicate(third))


if __name__ == "__main__":
    unittest.main()
