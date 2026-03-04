from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import Any


def _default(o: Any) -> Any:
    if is_dataclass(o):
        return asdict(o)
    # Fallback: try dict conversion
    if hasattr(o, "__dict__"):
        return o.__dict__
    return str(o)


def print_json(payload: Any) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=_default))
