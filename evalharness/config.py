"""Load YAML (or JSON sibling) config files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load(path: str | Path) -> Any:
    path = Path(path)
    if path.suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    try:
        import yaml  # type: ignore
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except ImportError:
        sibling = path.with_suffix(".json")
        if sibling.is_file():
            return json.loads(sibling.read_text(encoding="utf-8"))
        raise SystemExit(
            f"PyYAML is not installed and {sibling} is missing; install pyyaml or add a JSON sibling"
        )
