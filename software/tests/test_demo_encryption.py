from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from software.demo.encryption_demo import (
    BLOCK_64_KIB,
    CHUNK_32_KIB,
    DemoSafetyError,
    HEADER_SMALL_BYTES,
    SAFETY_MARKER_CONTENT,
    SAFETY_MARKER_NAME,
    common_cli_main,
    run_demo,
)


class DemoEncryptionTests(unittest.TestCase):
    def _target(self, root: Path) -> Path:
        target = root / "target"
        target.mkdir()
        (target / SAFETY_MARKER_NAME).write_text(
            SAFETY_MARKER_CONTENT,
            encoding="utf-8",
        )
        return target

    def test_full_encrypts_recursive_files_in_place(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = self._target(Path(temp_dir))
            nested = target / "nested"
            nested.mkdir()
            original = bytes(range(256)) * 40
            target_file = nested / "sample.bin"
            target_file.write_bytes(original)

            result = run_demo(
                target,
                "full",
                in_place=True,
                confirmed=True,
            )

            self.assertEqual(result.encrypted_files, 1)
            encrypted = target_file.read_bytes()
            self.assertEqual(len(encrypted), len(original))
            self.assertNotEqual(encrypted, original)

    def test_header_only_preserves_bytes_after_header(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = self._target(Path(temp_dir))
            original = bytes(range(256)) * 200
            target_file = target / "sample.bin"
            target_file.write_bytes(original)

            run_demo(
                target,
                "header-only",
                in_place=True,
                confirmed=True,
            )
            encrypted = target_file.read_bytes()

            self.assertNotEqual(encrypted[:HEADER_SMALL_BYTES], original[:HEADER_SMALL_BYTES])
            self.assertEqual(encrypted[HEADER_SMALL_BYTES:], original[HEADER_SMALL_BYTES:])

    def test_intermittent_uses_32_kib_chunks_with_64_kib_step(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = self._target(Path(temp_dir))
            original = bytes(range(256)) * 640
            target_file = target / "sample.bin"
            target_file.write_bytes(original)

            run_demo(
                target,
                "intermittent",
                in_place=True,
                confirmed=True,
            )
            encrypted = target_file.read_bytes()

            self.assertEqual(encrypted[:BLOCK_64_KIB], original[:BLOCK_64_KIB])
            first_end = BLOCK_64_KIB + CHUNK_32_KIB
            self.assertNotEqual(
                encrypted[BLOCK_64_KIB:first_end],
                original[BLOCK_64_KIB:first_end],
            )
            self.assertEqual(
                encrypted[first_end : 2 * BLOCK_64_KIB],
                original[first_end : 2 * BLOCK_64_KIB],
            )

    def test_hybrid_appends_hacked_over_existing_extension(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = self._target(Path(temp_dir))
            original = b"document-content" * 2000
            target_file = target / "document.pdf"
            target_file.write_bytes(original)

            run_demo(
                target,
                "hybrid",
                in_place=True,
                confirmed=True,
            )

            renamed = target / "document.pdf.hacked"
            self.assertTrue(renamed.is_file())
            self.assertFalse(target_file.exists())
            self.assertNotEqual(renamed.read_bytes(), original)

    def test_adaptive_fully_encrypts_file_not_larger_than_10_mib(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = self._target(Path(temp_dir))
            original = bytes(range(256)) * 100
            target_file = target / "sample.bin"
            target_file.write_bytes(original)

            run_demo(
                target,
                "adaptive",
                in_place=True,
                confirmed=True,
            )
            encrypted = target_file.read_bytes()

            self.assertEqual(len(encrypted), len(original))
            self.assertNotEqual(encrypted, original)

    def test_write_requires_in_place_flag_and_confirmation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = self._target(Path(temp_dir))
            target_file = target / "sample.bin"
            target_file.write_bytes(b"data")

            with self.assertRaises(DemoSafetyError):
                run_demo(target, "full", confirmed=True)
            self.assertEqual(target_file.read_bytes(), b"data")

            with self.assertRaises(DemoSafetyError):
                run_demo(target, "full", in_place=True)
            self.assertEqual(target_file.read_bytes(), b"data")

    def test_marker_is_required_and_never_encrypted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "target"
            target.mkdir()
            target_file = target / "sample.bin"
            target_file.write_bytes(b"data")

            with self.assertRaises(DemoSafetyError):
                run_demo(
                    target,
                    "full",
                    in_place=True,
                    confirmed=True,
                )
            self.assertEqual(target_file.read_bytes(), b"data")

            marker = target / SAFETY_MARKER_NAME
            marker.write_text(SAFETY_MARKER_CONTENT, encoding="utf-8")
            run_demo(
                target,
                "full",
                in_place=True,
                confirmed=True,
            )
            self.assertEqual(
                marker.read_text(encoding="utf-8"),
                SAFETY_MARKER_CONTENT,
            )

    def test_dry_run_does_not_change_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = self._target(Path(temp_dir))
            target_file = target / "sample.bin"
            target_file.write_bytes(b"data")

            result = run_demo(
                target,
                "full",
                in_place=True,
                dry_run=True,
            )

            self.assertTrue(result.dry_run)
            self.assertEqual(result.discovered_files, 1)
            self.assertEqual(result.selected_files, 1)
            self.assertEqual(target_file.read_bytes(), b"data")

    def test_files_count_changes_exact_number_and_leaves_remaining_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = self._target(Path(temp_dir))
            originals = {
                "a.bin": b"A" * 1024,
                "b.bin": b"B" * 1024,
                "c.bin": b"C" * 1024,
            }
            for name, content in originals.items():
                (target / name).write_bytes(content)

            result = run_demo(
                target,
                "full",
                files_count=2,
                in_place=True,
                confirmed=True,
            )

            self.assertEqual(result.discovered_files, 3)
            self.assertEqual(result.selected_files, 2)
            self.assertEqual(result.encrypted_files, 2)
            self.assertNotEqual((target / "a.bin").read_bytes(), originals["a.bin"])
            self.assertNotEqual((target / "b.bin").read_bytes(), originals["b.bin"])
            self.assertEqual((target / "c.bin").read_bytes(), originals["c.bin"])

    def test_files_count_larger_than_available_is_rejected_before_changes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = self._target(Path(temp_dir))
            target_file = target / "sample.bin"
            target_file.write_bytes(b"data")

            with self.assertRaises(DemoSafetyError):
                run_demo(
                    target,
                    "full",
                    files_count=2,
                    in_place=True,
                    confirmed=True,
                )
            self.assertEqual(target_file.read_bytes(), b"data")

    def test_hybrid_renames_only_selected_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = self._target(Path(temp_dir))
            (target / "a.pdf").write_bytes(b"A" * 20000)
            (target / "b.pdf").write_bytes(b"B" * 20000)

            result = run_demo(
                target,
                "hybrid",
                files_count=1,
                in_place=True,
                confirmed=True,
            )

            self.assertEqual(result.encrypted_files, 1)
            self.assertTrue((target / "a.pdf.hacked").is_file())
            self.assertFalse((target / "a.pdf").exists())
            self.assertTrue((target / "b.pdf").is_file())
            self.assertFalse((target / "b.pdf.hacked").exists())

    def test_common_cli_accepts_algorithm_as_first_argument(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = self._target(Path(temp_dir))
            target_file = target / "sample.bin"
            target_file.write_bytes(b"data")

            exit_code = common_cli_main(
                [
                    "full",
                    str(target),
                    "--in-place",
                    "--files_count",
                    "1",
                    "--dry-run",
                ]
            )

            self.assertEqual(exit_code, 0)
            self.assertEqual(target_file.read_bytes(), b"data")


if __name__ == "__main__":
    unittest.main()
