from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

import yaml


class InterfaceConfigurationError(ValueError):
    """The UI configuration cannot be resolved."""


@dataclass(frozen=True, slots=True)
class InterfaceOptions:
    config_path: Path
    database_path: Path


def default_config_path() -> Path:
    return Path(__file__).resolve().parents[1] / "configuration.yaml"


def parse_interface_options(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> InterfaceOptions:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--config", type=Path, default=default_config_path())
    parser.add_argument("--database", type=Path)
    args, _unknown = parser.parse_known_args(argv)

    environment = os.environ if environ is None else environ
    config_path = args.config.expanduser().resolve()

    database_override = args.database
    if database_override is None:
        environment_database = environment.get("SOFTWARE_UI_DATABASE")
        if environment_database:
            database_override = Path(environment_database)

    database_path = (
        database_override.expanduser().resolve()
        if database_override is not None
        else load_database_path(config_path)
    )
    return InterfaceOptions(
        config_path=config_path,
        database_path=database_path,
    )


def load_database_path(config_path: Path | str) -> Path:
    path = Path(config_path).expanduser().resolve()
    if not path.is_file():
        raise InterfaceConfigurationError(
            f"Файл конфигурации не найден: {path}"
        )
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise InterfaceConfigurationError(
            f"Не удалось прочитать конфигурацию: {path}"
        ) from exc

    if not isinstance(payload, Mapping):
        raise InterfaceConfigurationError(
            "Корень конфигурации должен быть YAML-объектом."
        )
    storage = payload.get("storage")
    if not isinstance(storage, Mapping):
        raise InterfaceConfigurationError(
            "В конфигурации отсутствует секция storage."
        )
    raw_database = storage.get("path")
    if raw_database in (None, ""):
        raise InterfaceConfigurationError(
            "В конфигурации отсутствует storage.path."
        )

    database_path = Path(str(raw_database)).expanduser()
    if not database_path.is_absolute():
        database_path = path.parent / database_path
    return database_path.resolve()

