from __future__ import annotations

import json
from typing import Any


def parse_json_payload(value: Any) -> tuple[bool, Any]:
    """Return parsed JSON, retaining malformed text for display."""
    if value is None or value == "":
        return True, None
    if not isinstance(value, str):
        return True, value
    try:
        return True, json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return False, value


def display_value(value: Any) -> Any:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.6f}"
    return value

