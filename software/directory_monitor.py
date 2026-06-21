from __future__ import annotations

import ctypes as ct
import ctypes.wintypes as wt
import logging
import struct
import sys
import threading
import uuid
from pathlib import Path
from typing import Callable

from .models import EventType, FileEvent, utc_now


FILE_LIST_DIRECTORY = 0x0001
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
FILE_NOTIFY_CHANGE_SIZE = 0x00000008
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
FILE_NOTIFY_CHANGE_CREATION = 0x00000040
INVALID_HANDLE_VALUE = ct.c_void_p(-1).value

ACTION_TO_EVENT_TYPE = {
    1: EventType.CREATED,
    2: EventType.DELETED,
    3: EventType.MODIFIED,
    4: EventType.MOVED,
    5: EventType.MOVED,
}


class WindowsDirectoryMonitor:
    def __init__(
        self,
        directories: tuple[Path, ...],
        callback: Callable[[FileEvent], None],
        *,
        logger: logging.Logger | None = None,
    ):
        self.directories = directories
        self.callback = callback
        self.logger = logger or logging.getLogger(
            "software.directory_monitor"
        )
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []
        self._handles: dict[Path, int] = {}
        self._lock = threading.RLock()
        self._kernel32 = None

    def start(self) -> None:
        if sys.platform != "win32":
            raise RuntimeError(
                "ReadDirectoryChangesW fallback is available only on Windows"
            )
        self._kernel32 = ct.WinDLL("kernel32", use_last_error=True)
        self._configure_api()
        for directory in self.directories:
            thread = threading.Thread(
                target=self._watch_directory,
                args=(directory,),
                name=f"directory-monitor-{directory.name}",
                daemon=True,
            )
            self._threads.append(thread)
            thread.start()
        self.logger.info(
            "ReadDirectoryChangesW fallback started directories=%s",
            [str(path) for path in self.directories],
        )

    def stop(self) -> None:
        self._stop_event.set()
        kernel32 = self._kernel32
        if kernel32 is not None:
            with self._lock:
                handles = list(self._handles.values())
            for handle in handles:
                kernel32.CancelIoEx(handle, None)
        for thread in self._threads:
            thread.join(timeout=3.0)
        self._threads.clear()
        self.logger.info("ReadDirectoryChangesW fallback stopped")

    def _watch_directory(self, directory: Path) -> None:
        kernel32 = self._kernel32
        handle = kernel32.CreateFileW(
            str(directory),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        if handle == INVALID_HANDLE_VALUE:
            self.logger.error(
                "Cannot watch directory=%s winerror=%s",
                directory,
                ct.get_last_error(),
            )
            return
        with self._lock:
            self._handles[directory] = handle
        buffer = ct.create_string_buffer(64 * 1024)
        bytes_returned = wt.DWORD()
        notify_filter = (
            FILE_NOTIFY_CHANGE_FILE_NAME
            | FILE_NOTIFY_CHANGE_DIR_NAME
            | FILE_NOTIFY_CHANGE_SIZE
            | FILE_NOTIFY_CHANGE_LAST_WRITE
            | FILE_NOTIFY_CHANGE_CREATION
        )
        try:
            while not self._stop_event.is_set():
                success = kernel32.ReadDirectoryChangesW(
                    handle,
                    buffer,
                    len(buffer),
                    True,
                    notify_filter,
                    ct.byref(bytes_returned),
                    None,
                    None,
                )
                if not success:
                    if self._stop_event.is_set():
                        break
                    self.logger.error(
                        "ReadDirectoryChangesW failed directory=%s winerror=%s",
                        directory,
                        ct.get_last_error(),
                    )
                    continue
                self._parse_notifications(
                    directory, buffer.raw[: bytes_returned.value]
                )
        finally:
            with self._lock:
                self._handles.pop(directory, None)
            kernel32.CloseHandle(handle)

    def _parse_notifications(self, directory: Path, data: bytes) -> None:
        offset = 0
        while offset + 12 <= len(data):
            next_offset, action, name_length = struct.unpack_from(
                "<III", data, offset
            )
            name_start = offset + 12
            name_end = name_start + name_length
            relative_name = data[name_start:name_end].decode(
                "utf-16-le", errors="replace"
            )
            event_type = ACTION_TO_EVENT_TYPE.get(action)
            if event_type is not None:
                self._emit(directory / relative_name, event_type)
            if next_offset == 0:
                break
            offset += next_offset

    def _emit(self, path: Path, event_type: EventType) -> None:
        try:
            if path.exists() and path.is_dir():
                return
        except OSError:
            pass
        file_size = None
        try:
            if path.is_file():
                file_size = path.stat().st_size
        except OSError:
            pass
        self.callback(
            FileEvent(
                event_id=str(uuid.uuid4()),
                event_type=event_type,
                timestamp=utc_now(),
                file_path=str(path),
                file_extension=path.suffix.lower(),
                file_size=file_size,
                process_id=None,
                process_name="unknown",
                process_key="unknown:directory-watcher",
            )
        )

    def _configure_api(self) -> None:
        kernel32 = self._kernel32
        kernel32.CreateFileW.argtypes = [
            wt.LPCWSTR,
            wt.DWORD,
            wt.DWORD,
            wt.LPVOID,
            wt.DWORD,
            wt.DWORD,
            wt.HANDLE,
        ]
        kernel32.CreateFileW.restype = wt.HANDLE
        kernel32.ReadDirectoryChangesW.argtypes = [
            wt.HANDLE,
            wt.LPVOID,
            wt.DWORD,
            wt.BOOL,
            wt.DWORD,
            ct.POINTER(wt.DWORD),
            wt.LPVOID,
            wt.LPVOID,
        ]
        kernel32.ReadDirectoryChangesW.restype = wt.BOOL
        kernel32.CancelIoEx.argtypes = [wt.HANDLE, wt.LPVOID]
        kernel32.CancelIoEx.restype = wt.BOOL
        kernel32.CloseHandle.argtypes = [wt.HANDLE]
        kernel32.CloseHandle.restype = wt.BOOL
