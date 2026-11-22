"""Source-file helpers: hashing, pragma, enclosing function."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Iterable, Optional

_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
_FUNC_RE = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("
)
_CTOR_RE = re.compile(r"\bconstructor\s*\(")
_OLD_CTOR_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*(?:public|internal|private|external)?")
_CONTRACT_RE = re.compile(r"\b(?:contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_text(path: Path) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", lambda m: " " * len(m.group(0)), text, flags=re.S)
    return re.sub(r"//[^\n]*", lambda m: " " * len(m.group(0)), text)


def pragma_constraint(text: str) -> Optional[str]:
    m = _PRAGMA_RE.search(strip_comments(text))
    return m.group(1).strip() if m else None


def function_at_line(text: str, line: int) -> Optional[str]:
    """Return the function (or constructor) that contains 1-indexed *line*."""
    if line <= 0:
        return None
    lines = text.splitlines()
    current: Optional[str] = None
    depth = 0
    started = False
    contract: Optional[str] = None
    for i, raw in enumerate(lines, start=1):
        code = strip_comments(raw)
        cm = _CONTRACT_RE.search(code)
        if cm and depth == 0:
            contract = cm.group(1)
        fm = _FUNC_RE.search(code)
        if fm:
            current = fm.group(1)
            started = True
        elif _CTOR_RE.search(code):
            current = "constructor"
            started = True
        # Very old Solidity used a function with the contract name as constructor.
        if current is None and contract and re.search(
            rf"\bfunction\s+{re.escape(contract)}\s*\(", code
        ):
            current = contract
            started = True
        if started:
            depth += code.count("{") - code.count("}")
            if depth <= 0 and "{" in "".join(lines[max(0, i - 20) : i]):
                # closed the function
                if i >= line:
                    return current
                current = None
                started = False
                depth = 0
        if i == line and current:
            return current
    return current if current else None


def functions_for_lines(text: str, lines: Iterable[int]) -> Optional[str]:
    found = []
    for ln in lines:
        fn = function_at_line(text, int(ln))
        if fn:
            found.append(fn)
    return found[0] if found else None
