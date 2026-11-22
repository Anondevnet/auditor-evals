"""Precision, recall, F1, clean FP rate, latency, and cost metrics."""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Optional, Sequence

from scoring.match import (
    ContractClassOutcome,
    Label,
    MatchResult,
    Prediction,
    clean_contract_ids,
    match_contract_level,
    match_line_level,
)


def _prf(tp: int, fp: int, fn: int) -> dict[str, Optional[float]]:
    prec = tp / (tp + fp) if (tp + fp) else None
    rec = tp / (tp + fn) if (tp + fn) else None
    if prec is None or rec is None or (prec + rec) == 0:
        f1 = None if (prec is None or rec is None) else 0.0
    else:
        f1 = 2 * prec * rec / (prec + rec)
    return {"precision": prec, "recall": rec, "f1": f1, "tp": tp, "fp": fp, "fn": fn}


def _mean(xs: Sequence[float]) -> Optional[float]:
    return (sum(xs) / len(xs)) if xs else None


def percentile(xs: Sequence[float], p: float) -> Optional[float]:
    if not xs:
        return None
    ys = sorted(xs)
    if p <= 0:
        return ys[0]
    if p >= 100:
        return ys[-1]
    k = (len(ys) - 1) * (p / 100.0)
    lo = math.floor(k)
    hi = math.ceil(k)
    if lo == hi:
        return ys[lo]
    return ys[lo] * (hi - k) + ys[hi] * (k - lo)


def cost_from_tokens(input_tokens: int, output_tokens: int, input_per_m: float, output_per_m: float) -> float:
    return (input_tokens / 1_000_000.0) * input_per_m + (output_tokens / 1_000_000.0) * output_per_m


def load_prices(path) -> dict:
    text = __import__("pathlib").Path(path).read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except Exception:
        import json
        j = __import__("pathlib").Path(path).with_suffix(".json")
        if j.is_file():
            return json.loads(j.read_text(encoding="utf-8"))
        raise


@dataclass
class RunMetrics:
    line: dict
    contract: dict
    per_class_line: dict
    per_class_contract: dict
    fp_rate_clean: Optional[float]
    findings_per_contract: float
    n_contracts: int
    n_clean: int
    n_findings: int
    compile_failures: int
    latency_p50_s: Optional[float]
    latency_p95_s: Optional[float]
    cost_total: float
    cost_per_contract: Optional[float]
    extras: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "line": self.line,
            "contract": self.contract,
            "per_class_line": self.per_class_line,
            "per_class_contract": self.per_class_contract,
            "fp_rate_clean": self.fp_rate_clean,
            "findings_per_contract": self.findings_per_contract,
            "n_contracts": self.n_contracts,
            "n_clean": self.n_clean,
            "n_findings": self.n_findings,
            "compile_failures": self.compile_failures,
            "latency_p50_s": self.latency_p50_s,
            "latency_p95_s": self.latency_p95_s,
            "cost_total": self.cost_total,
            "cost_per_contract": self.cost_per_contract,
            **self.extras,
        }


def score(
    labels: Sequence[Label],
    preds: Sequence[Prediction],
    *,
    contract_ids: Optional[Sequence[str]] = None,
    latencies_s: Optional[Mapping[str, float]] = None,
    costs: Optional[Mapping[str, float]] = None,
    compile_failed_ids: Optional[Sequence[str]] = None,
    classes: Optional[Sequence[str]] = None,
    window: int = 3,
) -> RunMetrics:
    labels = list(labels)
    preds = list(preds)
    if contract_ids is None:
        contract_ids = sorted({*(l.contract_id for l in labels), *(p.contract_id for p in preds)})
    compile_failed = set(compile_failed_ids or [])
    if classes is None:
        from evalharness.constants import DASP_CLASSES
        classes = list(DASP_CLASSES)

    line_res = match_line_level(labels, preds, window=window)
    line_overall = _prf(line_res.tp, line_res.fp, line_res.fn)

    per_class_line = {}
    for cls in classes:
        sub_g = [g for g in labels if g.label == "vulnerable" and g.vuln_class == cls]
        sub_p = [p for p in preds if p.vuln_class == cls]
        r = match_line_level(sub_g, sub_p, window=window)
        per_class_line[cls] = _prf(r.tp, r.fp, r.fn)

    cl_out = match_contract_level(labels, preds, classes=classes)
    # Restrict to known contract ids
    idset = set(contract_ids)
    cl_out = [o for o in cl_out if o.contract_id in idset]

    def _from_outcomes(rows: list[ContractClassOutcome]) -> dict:
        tp = sum(1 for o in rows if o.tag == "tp")
        fp = sum(1 for o in rows if o.tag == "fp")
        fn = sum(1 for o in rows if o.tag == "fn")
        return _prf(tp, fp, fn)

    # Micro over (contract, class) cells that are not both-negative? Standard
    # micro uses TP/FP/FN only (TN ignored) — correct.
    contract_overall = _from_outcomes(cl_out)
    per_class_contract = {
        cls: _from_outcomes([o for o in cl_out if o.vuln_class == cls])
        for cls in classes
    }

    def _macro(per_class: dict) -> dict:
        precs = [v["precision"] for v in per_class.values() if v["precision"] is not None]
        recs = [v["recall"] for v in per_class.values() if v["recall"] is not None]
        f1s = [v["f1"] for v in per_class.values() if v["f1"] is not None]
        return {"precision": _mean(precs), "recall": _mean(recs), "f1": _mean(f1s)}

    line_overall["micro"] = {k: line_overall[k] for k in ("precision", "recall", "f1")}
    line_overall["macro"] = _macro(per_class_line)
    contract_overall["micro"] = {k: contract_overall[k] for k in ("precision", "recall", "f1")}
    contract_overall["macro"] = _macro(per_class_contract)

    clean_ids = clean_contract_ids(labels) & idset
    dirty_clean = 0
    for cid in clean_ids:
        if any(p.contract_id == cid for p in preds):
            dirty_clean += 1
    fp_rate = (dirty_clean / len(clean_ids)) if clean_ids else None

    n_findings = len(preds)
    n_contracts = len(contract_ids)
    findings_per = n_findings / n_contracts if n_contracts else 0.0

    lat_list = [latencies_s[c] for c in contract_ids if latencies_s and c in latencies_s]
    cost_list = [costs[c] for c in contract_ids if costs and c in costs]
    total_cost = sum(cost_list) if cost_list else 0.0

    return RunMetrics(
        line=line_overall,
        contract=contract_overall,
        per_class_line=per_class_line,
        per_class_contract=per_class_contract,
        fp_rate_clean=fp_rate,
        findings_per_contract=findings_per,
        n_contracts=n_contracts,
        n_clean=len(clean_ids),
        n_findings=n_findings,
        compile_failures=len(compile_failed),
        latency_p50_s=percentile(lat_list, 50) if lat_list else None,
        latency_p95_s=percentile(lat_list, 95) if lat_list else None,
        cost_total=total_cost,
        cost_per_contract=(total_cost / n_contracts) if n_contracts else None,
        extras={
            "compile_failed_ids": sorted(compile_failed),
            "n_clean_with_finding": dirty_clean,
        },
    )


def mean_std(values: Sequence[float]) -> dict:
    xs = [v for v in values if v is not None]
    if not xs:
        return {"mean": None, "std": None, "n": 0}
    if len(xs) == 1:
        return {"mean": xs[0], "std": 0.0, "n": 1}
    return {"mean": statistics.mean(xs), "std": statistics.stdev(xs), "n": len(xs)}


def aggregate_runs(run_dicts: Sequence[Mapping]) -> dict:
    """Mean ± std over repeated runs for headline numbers."""
    def collect(path):
        out = []
        for d in run_dicts:
            cur = d
            for k in path:
                if cur is None:
                    break
                cur = cur.get(k) if isinstance(cur, Mapping) else None
            if isinstance(cur, (int, float)):
                out.append(float(cur))
        return out

    keys = {
        "line_precision": ("line", "precision"),
        "line_recall": ("line", "recall"),
        "line_f1": ("line", "f1"),
        "contract_precision": ("contract", "precision"),
        "contract_recall": ("contract", "recall"),
        "contract_f1": ("contract", "f1"),
        "fp_rate_clean": ("fp_rate_clean",),
        "cost_per_contract": ("cost_per_contract",),
        "latency_p50_s": ("latency_p50_s",),
        "latency_p95_s": ("latency_p95_s",),
        "findings_per_contract": ("findings_per_contract",),
    }
    return {name: mean_std(collect(path)) for name, path in keys.items()}
