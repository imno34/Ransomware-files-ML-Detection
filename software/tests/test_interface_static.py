from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from software.storage import RuntimeStorage


class InterfaceStaticTests(unittest.TestCase):
    def test_repository_contains_no_mutating_sql_or_runtime_storage(self):
        source = (
            Path(__file__).resolve().parents[1]
            / "interface"
            / "repository.py"
        ).read_text(encoding="utf-8")
        upper_source = source.upper()
        for token in (
            "INSERT INTO",
            "UPDATE ",
            "DELETE FROM",
            "CREATE TABLE",
            "DROP TABLE",
            "ALTER TABLE",
        ):
            self.assertNotIn(token, upper_source)
        self.assertNotIn("RuntimeStorage", source)

    def test_streamlit_app_smoke(self):
        try:
            from streamlit.testing.v1 import AppTest
        except ImportError:
            self.skipTest("Streamlit is not installed in the current interpreter")

        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "runtime.sqlite3"
            RuntimeStorage(database).close()
            app_path = (
                Path(__file__).resolve().parents[1]
                / "interface"
                / "app.py"
            )
            previous = os.environ.get("SOFTWARE_UI_DATABASE")
            os.environ["SOFTWARE_UI_DATABASE"] = str(database)
            try:
                app = AppTest.from_file(str(app_path), default_timeout=15)
                app.run()
                self.assertFalse(app.exception)
                self.assertEqual(
                    app.title[0].value,
                    "Результаты работы антивируса",
                )
                self.assertEqual(
                    tuple(app.radio[0].options),
                    ("Процессы", "Файловые события"),
                )
                app.radio[0].set_value("Файловые события").run()
                self.assertFalse(app.exception)
                self.assertTrue(
                    any(
                        header.value == "Файловые события"
                        for header in app.header
                    )
                )
            finally:
                if previous is None:
                    os.environ.pop("SOFTWARE_UI_DATABASE", None)
                else:
                    os.environ["SOFTWARE_UI_DATABASE"] = previous


if __name__ == "__main__":
    unittest.main()
