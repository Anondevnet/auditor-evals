"""Run the auditor's Slither + solc-select pipeline on one contract."""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

AUDITOR_SRC = Path(os.environ.get("AUDITOR_SRC", "/workspace/auditor-src"))
if str(AUDITOR_SRC) not in sys.path:
    sys.path.insert(0, str(AUDITOR_SRC))

from auditor.analysis.access_control import analyze as access_control_analyze
from auditor.analysis.base import AnalysisContext
from auditor.analysis.reentrancy import analyze as reentrancy_analyze
from auditor.analysis.slither_generic import analyze as slither_generic_analyze
from auditor.analysis.slither_runner import SLITHER_TIMEOUT_SECONDS, get_slither_run
from auditor.compiler_select import CompilerSelectionError, plan_compile
from evalharness.dasp import finding_to_dasp, slither_slug_to_dasp


@dataclass
class SlitherEvalResult:
    status: str  # completed | compile_failed | slither_failed | timeout
    findings: list[dict] = field(default_factory=list)
    solc_version: Optional[str] = None
    solc_path: Optional[str] = None
    latency_s: float = 0.0
    error: Optional[str] = None
    slither_status: Optional[str] = None
    n_detectors_raw: int = 0


def _finding_dict(finding, dasp: str, detector: Optional[str]) -> dict:
    return {
        "vuln_class": dasp,
        "detector": detector,
        "title": getattr(finding, "title", None),
        "function": getattr(finding, "affected_function", None),
        "contract": getattr(finding, "affected_contract", None),
        "lines": list(getattr(finding, "affected_lines", None) or []),
        "severity": getattr(getattr(finding, "severity", None), "value", None)
        or str(getattr(finding, "severity", "") or ""),
    }


def _detector_slug(finding) -> Optional[str]:
    title = str(getattr(finding, "title", "") or "")
    if title:
        token = title.split()[0]
        if token and token[0].islower() and "-" in token or token.startswith("reentrancy") or token.startswith("tx-"):
            return token
    desc = str(getattr(finding, "description", "") or "")
    marker = "detector: "
    if marker in desc.lower():
        import re
        m = re.search(r"detector:\s*([a-z0-9-]+)", desc, re.I)
        if m:
            return m.group(1)
    return token if title else None


def analyze_contract(sol_path: Path, timeout: Optional[float] = None) -> SlitherEvalResult:
    """Compile with the auditor's solc-select planner, then run Slither once."""
    sol_path = Path(sol_path).resolve()
    t0 = time.monotonic()
    timeout = float(timeout if timeout is not None else SLITHER_TIMEOUT_SECONDS)
    try:
        plan = plan_compile({}, [sol_path], sol_path.parent, allow_install=False)
    except CompilerSelectionError as exc:
        return SlitherEvalResult(
            status="compile_failed",
            error=f"compiler selection: {exc}",
            latency_s=time.monotonic() - t0,
        )
    except Exception as exc:  # noqa: BLE001
        return SlitherEvalResult(
            status="compile_failed",
            error=f"{type(exc).__name__}: {exc}",
            latency_s=time.monotonic() - t0,
        )

    options = {
        "solc": plan.solc_path,
        "solc_args": plan.solc_args,
        "solc_remaps": plan.solc_remaps,
        "slither_target": plan.target,
        "slither_cwd": plan.cwd,
        "scope": "all",
    }
    ctx = AnalysisContext()
    ctx.audit_id = "eval"
    ctx.source_files = [sol_path]
    ctx.options = options
    try:
        run = get_slither_run(ctx, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return SlitherEvalResult(
            status="slither_failed",
            solc_version=plan.version,
            solc_path=plan.solc_path,
            error=f"{type(exc).__name__}: {exc}",
            latency_s=time.monotonic() - t0,
        )

    if run.status in {"timeout"}:
        return SlitherEvalResult(
            status="timeout",
            solc_version=plan.version,
            solc_path=plan.solc_path,
            error=run.error,
            slither_status=run.status,
            latency_s=time.monotonic() - t0,
        )

    # Compiler / slither hard failures: the JSON report may still be missing.
    if run.status not in {"completed"} and not run.detectors:
        # Distinguish compile-time slither failures from other tool errors.
        err = (run.error or run.stderr or run.stdout or run.status or "")
        low = err.lower()
        status = "compile_failed" if any(
            s in low for s in ("compilererror", "parsererror", "solc", "source file requires different", "declarationerror")
        ) else "slither_failed"
        return SlitherEvalResult(
            status=status,
            solc_version=plan.version,
            solc_path=plan.solc_path,
            error=(run.error or err)[:500],
            slither_status=run.status,
            latency_s=time.monotonic() - t0,
        )

    findings = []
    for analyze in (reentrancy_analyze, access_control_analyze, slither_generic_analyze):
        try:
            outcome = analyze(ctx)
        except Exception:
            continue
        for f in outcome.findings or []:
            slug = _detector_slug(f)
            dasp = slither_slug_to_dasp(slug or "") if slug else finding_to_dasp({"title": getattr(f, "title", "")})
            findings.append(_finding_dict(f, dasp, slug))

    # If the specialized analyzers dropped everything but Slither produced
    # High/Medium/Low detectors, surface those too (auditor already does this
    # via slither_generic + the two families). Dedup by (slug, fn, lines).
    seen = {(d["detector"], d["function"], tuple(d["lines"])) for d in findings}
    raw = list(run.detectors or [])
    for det in raw:
        impact = str(det.get("impact") or "")
        if impact not in {"High", "Medium", "Low"}:
            continue
        slug = str(det.get("check") or "")
        from auditor.analysis.slither_runner import detector_location
        contract, function, lines = detector_location(det)
        key = (slug, function, tuple(int(x) for x in lines or []))
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "vuln_class": slither_slug_to_dasp(slug),
            "detector": slug,
            "title": f"{slug} in {contract}.{function}" if contract and function else slug,
            "function": function,
            "contract": contract,
            "lines": list(lines or []),
            "severity": impact.upper(),
        })

    return SlitherEvalResult(
        status="completed",
        findings=findings,
        solc_version=plan.version,
        solc_path=plan.solc_path,
        latency_s=time.monotonic() - t0,
        slither_status=run.status,
        n_detectors_raw=len(raw),
        error=None if run.status == "completed" else (run.error or run.status),
    )
