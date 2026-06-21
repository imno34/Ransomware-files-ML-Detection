from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import joblib

from software.bundle import BundleValidationError, RuntimeBundle


class RuntimeBundleTests(unittest.TestCase):
    def test_missing_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "broken.joblib"
            joblib.dump({"model": object()}, path)
            with self.assertRaisesRegex(BundleValidationError, "missing keys"):
                RuntimeBundle.load(path)

    def test_unreadable_bundle_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "broken.joblib"
            path.write_bytes(b"not-a-joblib-file")
            with self.assertRaisesRegex(BundleValidationError, "Cannot load"):
                RuntimeBundle.load(path)


if __name__ == "__main__":
    unittest.main()
