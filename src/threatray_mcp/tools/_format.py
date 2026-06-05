"""Shared JSON formatting helper for tools."""

import json
from typing import Any


def format_json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)
