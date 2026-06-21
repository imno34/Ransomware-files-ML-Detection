from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Sequence

from .bundle import RuntimeBundle, bundle_summary, current_feature_schema_hash
from .config import RuntimeConfig
from .logging_setup import close_logging, configure_logging
from .monitor import ETWUnavailableError, FileEventMonitor
from .pipeline import RuntimePipeline
from .replay import load_replay_events


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m software",
        description="ML-assisted ransomware detection prototype for Windows.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run live ETW monitoring.")
    _config_argument(run_parser)

    config_parser = subparsers.add_parser(
        "validate-config", help="Validate runtime YAML configuration."
    )
    _config_argument(config_parser)

    bundle_parser = subparsers.add_parser(
        "validate-bundle", help="Validate the configured trusted joblib bundle."
    )
    _config_argument(bundle_parser)
    bundle_parser.add_argument(
        "--bundle",
        type=Path,
        help="Optional bundle path overriding model.bundle_path.",
    )

    replay_parser = subparsers.add_parser(
        "replay", help="Process events from a JSON or JSONL file."
    )
    _config_argument(replay_parser)
    replay_parser.add_argument("--events", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    started_at = datetime.now().astimezone()
    args = build_parser().parse_args(argv)
    logger = None
    try:
        config = RuntimeConfig.load(args.config)
        if args.command == "validate-config":
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "config": str(config.source_path),
                        "feature_schema_hash": current_feature_schema_hash(),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0

        bundle_path = (
            args.bundle
            if args.command == "validate-bundle" and args.bundle is not None
            else config.model.bundle_path
        )
        bundle = RuntimeBundle.load(bundle_path)
        if args.command == "validate-bundle":
            print(
                json.dumps(
                    {"status": "ok", **bundle_summary(bundle)},
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0

        logger = configure_logging(config.logging, started_at=started_at)
        if args.command == "replay":
            return asyncio.run(_run_replay(config, bundle, args.events, logger))
        if args.command == "run":
            if sys.platform != "win32":
                raise ETWUnavailableError("The run command requires Windows")
            _validate_live_directories(config)
            return asyncio.run(_run_live(config, bundle, logger))
        raise RuntimeError(f"Unsupported command: {args.command}")
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    finally:
        if logger is not None:
            close_logging(logger)


async def _run_replay(config, bundle, events_path: Path, logger) -> int:
    events = load_replay_events(events_path)
    pipeline = RuntimePipeline(config, bundle, logger=logger.getChild("pipeline"))
    await pipeline.start()
    try:
        for event in events:
            await pipeline.submit(event)
        await pipeline.join()
        print(
            json.dumps(
                {
                    "status": "ok",
                    "submitted_events": len(events),
                    "stored_events": pipeline.storage.count_events(),
                    "database": str(config.storage.path),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    finally:
        await pipeline.stop()
    return 0


async def _run_live(config, bundle, logger) -> int:
    pipeline = RuntimePipeline(config, bundle, logger=logger.getChild("pipeline"))
    await pipeline.start()
    monitor = FileEventMonitor(
        config.monitor,
        pipeline.submit_threadsafe,
        logger=logger.getChild("monitor"),
    )
    try:
        monitor.start()
        # asyncio.run() installs the platform-appropriate SIGINT handler.
        # Ctrl+C cancels this task and the finally block performs cleanup.
        await asyncio.Future()
    finally:
        monitor.stop()
        await pipeline.stop()
    return 0


def _config_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", type=Path, required=True)


def _validate_live_directories(config: RuntimeConfig) -> None:
    missing = [
        str(path)
        for path in config.monitor.monitored_directories
        if not path.is_dir()
    ]
    if missing:
        raise FileNotFoundError(
            f"Monitored directories do not exist: {missing}"
        )


if __name__ == "__main__":
    raise SystemExit(main())
