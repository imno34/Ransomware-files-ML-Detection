from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from software.config import MonitorConfig
from software.models import EventType
from software.monitor import (
    FileEventMonitor,
    _build_trace_properties,
    _decode_kernel_file_payload,
    _merge_callback_payload,
)


class MonitorNormalizationTests(unittest.TestCase):
    def test_fallback_only_mode_does_not_start_etw(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            monitor = FileEventMonitor(
                MonitorConfig(
                    monitored_directories=(root,),
                    etw_enabled=False,
                    directory_fallback_enabled=True,
                ),
                lambda _event: None,
            )
            with (
                patch("software.monitor.sys.platform", "win32"),
                patch("software.monitor.WindowsDirectoryMonitor") as fallback,
            ):
                monitor.start()
                fallback.assert_called_once()
                fallback.return_value.start.assert_called_once_with()
                monitor.stop()
                fallback.return_value.stop.assert_called_once_with()

    def test_pywintrace_callback_tuple_and_nested_header_are_supported(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "sample.txt"
            path.write_text("payload", encoding="utf-8")
            monitor = FileEventMonitor(
                MonitorConfig(monitored_directories=(root,)),
                lambda _event: None,
            )
            callback_payload = (
                16,
                {
                    "EventHeader": {
                        "ProcessId": 99999999,
                        "ThreadId": 7,
                        "TimeStamp": 133_000_000_000_000_000,
                        "EventDescriptor": {"Id": 16},
                    },
                    "Task Name": "FileIo/Write",
                    "FileName": str(path),
                },
            )
            raw = _merge_callback_payload((callback_payload,), {})
            event = monitor.normalize_event(raw)
            self.assertIsNotNone(event)
            self.assertEqual(event.event_type, EventType.MODIFIED)
            self.assertEqual(event.thread_id, 7)
            self.assertEqual(event.process_id, 99999999)
            self.assertEqual(Path(event.file_path), path)

    def test_name_create_correlates_file_key_with_write_event(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "correlated.txt"
            path.write_text("payload", encoding="utf-8")
            monitor = FileEventMonitor(
                MonitorConfig(monitored_directories=(root,)),
                lambda _event: None,
            )
            name_event = {
                "event_id": 10,
                "EventHeader": {
                    "ProcessId": 4,
                    "ThreadId": 1,
                    "TimeStamp": 133_000_000_000_000_000,
                    "EventDescriptor": {"Id": 10},
                },
                "Task Name": "NameCreate",
                "FileKey": "0x1234",
                "FileName": str(path),
            }
            write_event = {
                "event_id": 16,
                "EventHeader": {
                    "ProcessId": 99999999,
                    "ThreadId": 7,
                    "TimeStamp": 133_000_000_000_000_100,
                    "EventDescriptor": {"Id": 16},
                },
                "Task Name": "Write",
                "FileKey": "0x1234",
            }
            self.assertIsNone(monitor.consume_raw_event(name_event))
            event = monitor.consume_raw_event(write_event)
            self.assertIsNotNone(event)
            self.assertEqual(event.event_type, EventType.MODIFIED)
            self.assertEqual(Path(event.file_path), path)

    def test_create_correlates_file_object_with_write_event(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "file-object.txt"
            path.write_text("payload", encoding="utf-8")
            monitor = FileEventMonitor(
                MonitorConfig(monitored_directories=(root,)),
                lambda _event: None,
            )
            create_event = {
                "event_id": 12,
                "EventHeader": {
                    "ProcessId": 99999999,
                    "ThreadId": 7,
                    "TimeStamp": 133_000_000_000_000_000,
                    "EventDescriptor": {"Id": 12},
                },
                "Task Name": "Create",
                "FileObject": "0xFFFF00001234",
                "FileName": str(path),
            }
            write_event = {
                "event_id": 16,
                "EventHeader": {
                    "ProcessId": 99999999,
                    "ThreadId": 7,
                    "TimeStamp": 133_000_000_000_000_100,
                    "EventDescriptor": {"Id": 16},
                },
                "Task Name": "Write",
                "FileObject": "0xFFFF00001234",
            }

            created = monitor.consume_raw_event(create_event)
            modified = monitor.consume_raw_event(write_event)

            self.assertIsNone(created)
            self.assertIsNotNone(modified)
            self.assertEqual(modified.event_type, EventType.MODIFIED)
            self.assertEqual(Path(modified.file_path), path)
            self.assertEqual(modified.process_id, 99999999)

    def test_fast_kernel_file_payload_decoder(self):
        file_key = 0xFFFFA20012345678
        file_object = 0xFFFF808F12345678
        path = r"\Device\HarddiskVolume3\test\sample.bin"

        name_payload = (
            file_key.to_bytes(8, "little")
            + path.encode("utf-16-le")
            + b"\x00\x00"
        )
        create_payload = (
            struct.pack(
                "<QQIIII",
                0x1000,
                file_object,
                77,
                0x60,
                0x80,
                7,
            )
            + path.encode("utf-16-le")
            + b"\x00\x00"
        )
        write_payload = struct.pack(
            "<QQQQIIII",
            0,
            0x2000,
            file_object,
            file_key,
            77,
            32768,
            0x60043,
            0,
        )

        name = _decode_kernel_file_payload(10, name_payload)
        create = _decode_kernel_file_payload(12, create_payload)
        write = _decode_kernel_file_payload(16, write_payload)

        self.assertEqual(name["FileName"], path)
        self.assertEqual(name["FileKey"], f"0x{file_key:X}")
        self.assertEqual(create["FileObject"], f"0x{file_object:X}")
        self.assertEqual(create["FileName"], path)
        self.assertEqual(write["FileObject"], f"0x{file_object:X}")
        self.assertEqual(write["FileKey"], f"0x{file_key:X}")
        self.assertEqual(write["IOSize"], 32768)

    def test_system_logger_trace_property_is_enabled(self):
        class Contents:
            LogFileMode = 0x100

        class Wrapper:
            contents = Contents()

        class TraceProperties:
            def get(self):
                return Wrapper()

        class Constants:
            EVENT_TRACE_SYSTEM_LOGGER_MODE = 0x02000000

        class EtwImplementation:
            et = Constants()

            @staticmethod
            def TraceProperties():
                return TraceProperties()

        properties = _build_trace_properties(
            EtwImplementation,
            system_logger_mode=True,
        )

        self.assertEqual(
            properties.get().contents.LogFileMode,
            0x100 | 0x02000000,
        )
        self.assertIsNone(
            _build_trace_properties(
                EtwImplementation,
                system_logger_mode=False,
            )
        )

    def test_stop_closes_consumer_before_provider(self):
        order = []

        class Component:
            def __init__(self, name):
                self.name = name

            def stop(self):
                order.append(self.name)

        class Job:
            running = True
            consumer = Component("consumer")
            provider = Component("provider")

        monitor = FileEventMonitor(
            MonitorConfig(monitored_directories=(Path(tempfile.gettempdir()),)),
            lambda _event: None,
        )
        monitor._job = Job()
        monitor.stop()
        self.assertEqual(order, ["consumer", "provider"])


if __name__ == "__main__":
    unittest.main()
