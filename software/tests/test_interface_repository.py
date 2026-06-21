from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from software.interface.formatting import parse_json_payload
from software.interface.repository import (
    DatabaseNotFoundError,
    DatabaseSchemaError,
    EventFilters,
    InterfaceDatabaseError,
    ProcessFilters,
    ReadOnlyRepository,
)
from software.interface.settings import (
    InterfaceConfigurationError,
    load_database_path,
    parse_interface_options,
)
from software.storage import RuntimeStorage


class InterfaceRepositoryTests(unittest.TestCase):
    def _database(self, root: Path) -> Path:
        database = root / "runtime.sqlite3"
        RuntimeStorage(database).close()
        return database

    def _insert_process(
        self,
        connection: sqlite3.Connection,
        *,
        index: int,
        name: str = "sample.exe",
        threat: str = "low",
        status: str = "active",
    ) -> str:
        process_key = f"{1000 + index}:process-{index}"
        connection.execute(
            """
            INSERT INTO processes (
                process_key, process_id, process_name, process_start_time,
                first_seen, last_seen, window_start, window_size,
                events_in_window, classified_events_count, benign_count,
                benign_encrypted_count, ransomware_encrypted_count,
                consecutive_ransomware_hits, ransomware_ratio,
                max_ransomware_probability, avg_ransomware_probability,
                touched_files, touched_files_unique, suspicion_score,
                threat_level, decision_reason, last_event_id, profile_status
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, 30, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?
            )
            """,
            (
                process_key,
                1000 + index,
                name,
                "2026-06-21T09:00:00+00:00",
                "2026-06-21T09:00:00+00:00",
                f"2026-06-21T09:{index % 60:02d}:00+00:00",
                "2026-06-21T09:00:00+00:00",
                index + 1,
                index + 1,
                max(0, index - 1),
                0,
                1 if threat in {"high", "critical"} else 0,
                1 if threat in {"high", "critical"} else 0,
                0.5 if threat in {"high", "critical"} else 0.0,
                0.95 if threat == "critical" else 0.4,
                0.75 if threat == "critical" else 0.2,
                index + 1,
                index + 1,
                min(100, index * 10),
                threat,
                "test",
                f"event-{index}",
                status,
            ),
        )
        return process_key

    def _insert_event(
        self,
        connection: sqlite3.Connection,
        *,
        index: int,
        process_key: str,
        predicted_class: str = "benign",
        features_json: str = '{"value":1}',
    ) -> str:
        event_id = f"event-{index}"
        connection.execute(
            """
            INSERT INTO file_events (
                event_id, event_type, timestamp, file_path, file_extension,
                file_size, process_id, process_name, process_key,
                filter_decision, event_priority, stabilization_status,
                stabilization_attempts, extraction_status, features_json,
                vectorization_status, feature_vector_json, predicted_class,
                ransomware_encrypted_probability, response_status
            ) VALUES (
                ?, 'modified', ?, ?, '.bin', 1024, ?, 'sample.exe', ?,
                'pass', 'normal', 'stable', 3, 'success', ?,
                'success', '[1.0]', ?, ?, 'logged'
            )
            """,
            (
                event_id,
                f"2026-06-21T10:{index % 60:02d}:00+00:00",
                f"C:/test/file-{index}.bin",
                int(process_key.split(":", 1)[0]),
                process_key,
                features_json,
                predicted_class,
                0.95 if predicted_class == "ransomware-encrypted" else 0.05,
            ),
        )
        return event_id

    def test_reads_processes_events_and_relationship(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = self._database(Path(temp_dir))
            with closing(sqlite3.connect(database)) as connection:
                process_key = self._insert_process(
                    connection,
                    index=1,
                    name="encryptor.exe",
                    threat="critical",
                )
                event_id = self._insert_event(
                    connection,
                    index=1,
                    process_key=process_key,
                    predicted_class="ransomware-encrypted",
                )
                connection.commit()

            repository = ReadOnlyRepository(database)
            repository.validate_schema()
            processes = repository.list_processes(
                ProcessFilters(
                    search="encryptor",
                    threat_levels=("critical",),
                )
            )
            events = repository.list_process_events(process_key)

            self.assertEqual(processes.total, 1)
            self.assertEqual(processes.items[0]["process_key"], process_key)
            self.assertEqual(events.total, 1)
            self.assertEqual(events.items[0]["event_id"], event_id)
            self.assertEqual(repository.get_event(event_id)["process_key"], process_key)
            self.assertEqual(
                repository.summary(),
                {
                    "processes": 1,
                    "events": 1,
                    "critical_processes": 1,
                    "ransomware_events": 1,
                },
            )

    def test_event_filters_and_pagination_are_applied_server_side(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = self._database(Path(temp_dir))
            with closing(sqlite3.connect(database)) as connection:
                process_key = self._insert_process(connection, index=1)
                for index in range(30):
                    self._insert_event(
                        connection,
                        index=index,
                        process_key=process_key,
                        predicted_class=(
                            "ransomware-encrypted" if index < 26 else "benign"
                        ),
                    )
                connection.commit()

            repository = ReadOnlyRepository(database)
            page = repository.list_events(
                EventFilters(
                    search="file-",
                    event_types=("modified",),
                    predicted_classes=("ransomware-encrypted",),
                    extraction_statuses=("success",),
                    vectorization_statuses=("success",),
                ),
                page=2,
                page_size=25,
            )

            self.assertEqual(page.total, 26)
            self.assertEqual(page.page, 2)
            self.assertEqual(page.total_pages, 2)
            self.assertEqual(len(page.items), 1)

    def test_query_only_connection_rejects_writes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = self._database(Path(temp_dir))
            repository = ReadOnlyRepository(database)

            with self.assertRaises(InterfaceDatabaseError):
                with repository._connect() as connection:
                    connection.execute("DELETE FROM file_events")

    def test_new_connections_observe_committed_wal_changes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = self._database(Path(temp_dir))
            repository = ReadOnlyRepository(database)
            self.assertEqual(repository.summary()["processes"], 0)

            with closing(sqlite3.connect(database)) as writer:
                writer.execute("PRAGMA journal_mode=WAL")
                self._insert_process(writer, index=1)
                writer.commit()

            self.assertEqual(repository.summary()["processes"], 1)

    def test_missing_corrupt_and_incompatible_databases_are_reported(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with self.assertRaises(DatabaseNotFoundError):
                ReadOnlyRepository(root / "missing.sqlite3").validate_schema()

            incompatible = root / "incompatible.sqlite3"
            with closing(sqlite3.connect(incompatible)) as connection:
                connection.execute("CREATE TABLE unrelated (value TEXT)")
                connection.commit()
            with self.assertRaises(DatabaseSchemaError):
                ReadOnlyRepository(incompatible).validate_schema()

            corrupt = root / "corrupt.sqlite3"
            corrupt.write_bytes(b"not-a-sqlite-database")
            with self.assertRaises(InterfaceDatabaseError):
                ReadOnlyRepository(corrupt).validate_schema()

    def test_json_payload_keeps_malformed_source(self):
        self.assertEqual(parse_json_payload('{"value": 1}'), (True, {"value": 1}))
        self.assertEqual(parse_json_payload("{broken"), (False, "{broken"))
        self.assertEqual(parse_json_payload(None), (True, None))


class InterfaceSettingsTests(unittest.TestCase):
    def test_database_path_is_loaded_relative_to_config(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "runtime.yaml"
            config.write_text(
                "storage:\n  path: data/runtime.sqlite3\n",
                encoding="utf-8",
            )
            self.assertEqual(
                load_database_path(config),
                (root / "data/runtime.sqlite3").resolve(),
            )

    def test_database_argument_overrides_config(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = root / "runtime.yaml"
            config.write_text(
                "storage:\n  path: configured.sqlite3\n",
                encoding="utf-8",
            )
            override = root / "override.sqlite3"
            options = parse_interface_options(
                [
                    "--config",
                    str(config),
                    "--database",
                    str(override),
                ],
                environ={},
            )
            self.assertEqual(options.database_path, override.resolve())

    def test_invalid_config_is_reported(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config = Path(temp_dir) / "runtime.yaml"
            config.write_text("model: {}\n", encoding="utf-8")
            with self.assertRaises(InterfaceConfigurationError):
                load_database_path(config)


if __name__ == "__main__":
    unittest.main()
