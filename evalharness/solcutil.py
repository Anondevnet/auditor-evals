"""Pragma resolution against solc-select, with a fallback if auditor-src is absent."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

_AUDITOR = Path(os.environ.get("AUDITOR_SRC", str(Path(__file__).resolve().parents[2] / "contract-auditor")))
if _AUDITOR.is_dir() and str(_AUDITOR) not in sys.path:
    sys.path.insert(0, str(_AUDITOR))

try:
    from auditor.compiler_select import (  # type: ignore
        choose_pragma_version,
        ensure_solc,
        installed_versions,
        pragma_constraints,
        artifact_path,
        VERSION_RE,
        CompilerSelectionError,
    )
    _HAS_AUDITOR = True
except Exception:  # pragma: no cover - harness still works for unit tests
    _HAS_AUDITOR = False
    CompilerSelectionError = RuntimeError  # type: ignore
    VERSION_RE = __import__("re").compile(r"^\d+\.\d+\.\d+$")

    def installed_versions(root=None):
        return []

    def choose_pragma_version(constraints, installed):
        return None

    def ensure_solc(version, allow_install=True, installer=None, root=None):
        raise RuntimeError("auditor.compiler_select unavailable")

    def pragma_constraints(sources):
        from evalharness.source import pragma_constraint
        return [c for c in (pragma_constraint(s) for s in sources) if c]

    def artifact_path(version, root=None):
        return Path.home() / ".solc-select" / "artifacts" / f"solc-{version}" / f"solc-{version}"


def available_solc_versions() -> List[str]:
    return list(installed_versions())


def version_for_source(text: str, installed: Optional[Sequence[str]] = None) -> Optional[str]:
    """Pick the highest installed (or known) solc that satisfies the pragma."""
    constraints = pragma_constraints([text])
    if not constraints:
        return None
    inst = list(installed if installed is not None else installed_versions())
    return choose_pragma_version(constraints, inst)


def solc_binary(version: str, allow_install: bool = False) -> str:
    return ensure_solc(version, allow_install=allow_install)


def try_compile(source_path: Path, solc_path: str, timeout: float = 12.0) -> Tuple[bool, str]:
    """Compile a single file with a specific solc binary. No network."""
    source_path = Path(source_path)
    try:
        with tempfile.TemporaryDirectory(prefix="eval-solc-") as tmp:
            proc = subprocess.run(
                [solc_path, "--bin", "-o", tmp, str(source_path.name)],
                cwd=str(source_path.parent),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        if proc.returncode == 0:
            return True, ""
        err = (proc.stderr or proc.stdout or "").strip().splitlines()
        return False, (err[-1] if err else f"solc exit {proc.returncode}")[:300]
    except subprocess.TimeoutExpired:
        return False, f"solc timed out after {timeout:g}s"
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"
