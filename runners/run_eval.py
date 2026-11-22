#!/usr/bin/env python3
"""Run an eval configuration over datasets/manifest.jsonl.

  python runners/run_eval.py --model slither
  python runners/run_eval.py --table-only --run-dir results/<id>

Paid models are wired but will not call a paid API in this workstream.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evalharness.config import load
from evalharness.constants import DASP_CLASSES
from evalharness.source import read_text
from runners.prompts import SYSTEM, build_user_prompt
from runners.providers import get_provider
from runners.providers.base import ProviderError, SpendCapExceeded
from runners.slither_backend import analyze_contract
from runners.tokens import count_tokens, encoding_name
from scoring.match import Label, Prediction
from scoring.metrics import cost_from_tokens, score

DETROIT = ZoneInfo("America/Detroit")


def _now() -> str:
    return datetime.now(DETROIT).isoformat(timespec="seconds")


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def labels_from_jsonl(path: Path) -> list[Label]:
    rows = load_jsonl(path)
    out = []
    for r in rows:
        out.append(Label(
            contract_id=r["contract_id"],
            vuln_class=r.get("vuln_class"),
            lines=tuple(int(x) for x in (r.get("lines") or [])),
            function=r.get("function"),
            label=r.get("label") or "vulnerable",
        ))
    return out


def fmt(x, digits=3):
    if x is None:
        return "—"
    if isinstance(x, float):
        return f"{x:.{digits}f}"
    return str(x)


def money(x):
    if x is None:
        return "—"
    if abs(x) < 1e-9:
        return "$0"
    return f"${x:.4f}"


def write_table(metrics: dict, *, run_id: str, pins: dict, n_manifest: int, path: Path, system_name: str) -> None:
    line = metrics["line"]
    lat50, lat95 = metrics.get("latency_p50_s"), metrics.get("latency_p95_s")
    rows = [
        "# Eval results",
        "",
        f"Run `{run_id}` — {system_name} — {_now()} (America/Detroit)",
        "",
        "| System | Precision | Recall | F1 | FP rate (clean) | $/contract | p50 s | p95 s |",
        "|---|---|---|---|---|---|---|---|",
        "| {sys} | {p} | {r} | {f} | {fp} | {cost} | {p50} | {p95} |".format(
            sys=system_name,
            p=fmt(line.get("precision")),
            r=fmt(line.get("recall")),
            f=fmt(line.get("f1")),
            fp=fmt(metrics.get("fp_rate_clean")),
            cost=money(metrics.get("cost_per_contract")),
            p50=fmt(lat50, 2),
            p95=fmt(lat95, 2),
        ),
        "",
        "Line-level micro/macro (matching rule: same DASP class and ±3 lines or same function):",
        "",
        f"- micro P/R/F1 = {fmt(line.get('micro', {}).get('precision'))} / "
        f"{fmt(line.get('micro', {}).get('recall'))} / {fmt(line.get('micro', {}).get('f1'))}",
        f"- macro P/R/F1 = {fmt(line.get('macro', {}).get('precision'))} / "
        f"{fmt(line.get('macro', {}).get('recall'))} / {fmt(line.get('macro', {}).get('f1'))}",
        "",
        "Contract-level micro/macro:",
        "",
        f"- micro P/R/F1 = {fmt(metrics['contract'].get('micro', {}).get('precision'))} / "
        f"{fmt(metrics['contract'].get('micro', {}).get('recall'))} / {fmt(metrics['contract'].get('micro', {}).get('f1'))}",
        f"- macro P/R/F1 = {fmt(metrics['contract'].get('macro', {}).get('precision'))} / "
        f"{fmt(metrics['contract'].get('macro', {}).get('recall'))} / {fmt(metrics['contract'].get('macro', {}).get('f1'))}",
        "",
        f"Findings/contract: {fmt(metrics.get('findings_per_contract'), 2)}. "
        f"Compile failures: {metrics.get('compile_failures', 0)} / {metrics.get('n_contracts', 0)}. "
        f"Slither tool failures: {metrics.get('slither_failure_count', 0)} / {metrics.get('n_contracts', 0)} "
        f"(timeouts: {metrics.get('timeout_count', 0)}). "
        f"Failures are tracked in raw.jsonl and scored as zero findings, not dropped.",
        "",
        "## Per-class F1 (line-level)",
        "",
        "| Class | Precision | Recall | F1 | TP | FP | FN |",
        "|---|---|---|---|---|---|---|",
    ]
    for cls, vals in metrics.get("per_class_line", {}).items():
        rows.append(
            f"| {cls} | {fmt(vals.get('precision'))} | {fmt(vals.get('recall'))} | "
            f"{fmt(vals.get('f1'))} | {vals.get('tp')} | {vals.get('fp')} | {vals.get('fn')} |"
        )
    rows += [
        "",
        "## Per-class F1 (contract-level)",
        "",
        "| Class | Precision | Recall | F1 | TP | FP | FN |",
        "|---|---|---|---|---|---|---|",
    ]
    for cls, vals in metrics.get("per_class_contract", {}).items():
        rows.append(
            f"| {cls} | {fmt(vals.get('precision'))} | {fmt(vals.get('recall'))} | "
            f"{fmt(vals.get('f1'))} | {vals.get('tp')} | {vals.get('fp')} | {vals.get('fn')} |"
        )
    curated = (pins.get("commits") or {}).get("smartbugs-curated", {})
    solidifi = (pins.get("commits") or {}).get("SolidiFI-benchmark", {})
    wild = (pins.get("commits") or {}).get("smartbugs-wild", {})
    counts = (pins.get("manifest") or {}).get("counts") or {}
    slither_ids = metrics.get("slither_failed_ids") or []
    if slither_ids:
        rows += [
            "",
            "## Failures",
            "",
            "These files compiled with the selected solc (confirmed separately) but Slither "
            "0.11.2 crashed. They are scored as zero findings, not dropped:",
            "",
        ]
        for cid in slither_ids:
            rows.append(f"- `{cid}`")
    rows += [
        "",
        f"Dataset: SmartBugs Curated @`{curated.get('commit', '?')[:12]}`, "
        f"SolidiFI @`{solidifi.get('commit', '?')[:12]}`, "
        f"Wild @`{wild.get('commit', '?')[:12]}`, "
        f"n={counts.get('total', n_manifest)} "
        f"(curated={counts.get('smartbugs-curated')}, "
        f"solidifi={counts.get('solidifi')}, wild={counts.get('smartbugs-wild')}). "
        f"Seed={pins.get('sample_seed')}.",
        "",
    ]
    path.write_text("\n".join(rows), encoding="utf-8")


def estimate_tokens(manifest, raw_by_id, prices) -> dict:
    inputs = []
    output_est = []
    for m in manifest:
        rec = raw_by_id.get(m["contract_id"]) or {}
        src_path = ROOT / m["path"]
        source = read_text(src_path) if src_path.is_file() else ""
        findings = rec.get("findings") or []
        user = build_user_prompt(m["contract_id"], source, findings, rec.get("solc_version") or m.get("solc_version"))
        # Chat-style: system + user
        inn = count_tokens(SYSTEM) + count_tokens(user)
        inputs.append(inn)
        # Structured JSON triage: ~80 tokens/finding + 60 overhead (estimate only).
        output_est.append(60 + 80 * max(1, len(findings)))
    n = len(inputs) or 1
    avg_in = sum(inputs) / n
    avg_out = sum(output_est) / n
    spec_in, spec_out = 6000.0, 1500.0
    paid = {
        "gpt-6.1-sol": prices["models"]["gpt-6.1-sol"],
        "gpt-6.1-terra": prices["models"]["gpt-6.1-terra"],
        "claude-sonnet-5.5": prices["models"]["claude-sonnet-5.5"],
        "claude-haiku-5.5": prices["models"]["claude-haiku-5.5"],
    }
    projections = {}
    multiplier_claude = float(prices.get("claude_token_multiplier") or 1.3)
    for name, row in paid.items():
        mult = multiplier_claude if row.get("provider") == "anthropic" else 1.0
        def pack(avg_i, avg_o, discount=1.0):
            per = cost_from_tokens(int(round(avg_i * mult)), int(round(avg_o * mult)),
                                   row["input_per_million"], row["output_per_million"]) * discount
            one = per * n
            three = one * 3
            return {
                "usd_per_contract": per,
                "usd_one_pass": one,
                "usd_three_runs": three,
                "within_40": three <= float(prices.get("budget_usd") or 40),
            }
        projections[name] = {
            "measured_input_plus_estimated_output": pack(avg_in, avg_out),
            "measured_input_plus_estimated_output_batch50": pack(avg_in, avg_out, 0.5),
            "spec_6k_1_5k": pack(spec_in, spec_out),
            "spec_6k_1_5k_batch50": pack(spec_in, spec_out, 0.5),
        }
    return {
        "tokenizer": encoding_name(),
        "n_contracts": n,
        "avg_input_tokens": avg_in,
        "avg_output_tokens_estimated": avg_out,
        "spec_assumed_input": spec_in,
        "spec_assumed_output": spec_out,
        "p50_input": sorted(inputs)[len(inputs)//2] if inputs else 0,
        "p95_input": sorted(inputs)[int((len(inputs)-1)*0.95)] if inputs else 0,
        "max_input": max(inputs) if inputs else 0,
        "min_input": min(inputs) if inputs else 0,
        "projections_usd": projections,
        "budget_usd": prices.get("budget_usd"),
    }


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--model", default="slither", help="system key from config/models.yaml")
    p.add_argument("--manifest", type=Path, default=ROOT / "datasets" / "manifest.jsonl")
    p.add_argument("--labels", type=Path, default=ROOT / "labels" / "all.jsonl")
    p.add_argument("--run-id")
    p.add_argument("--run-dir", type=Path)
    p.add_argument("--max-spend", type=float, help="override hard per-run spend cap (USD)")
    p.add_argument("--timeout", type=float, default=90.0)
    p.add_argument("--limit", type=int, help="optional cap on contracts (debug)")
    p.add_argument("--table-only", action="store_true")
    p.add_argument("--rescore", action="store_true",
                   help="recompute metrics.json + table.md from an existing raw.jsonl")
    return p.parse_args()


def score_run(raw_rows: list[dict], manifest: list[dict], labels, pins: dict, prices: dict,
              run_dir: Path, run_id: str, system_key: str, system_name: str) -> dict:
    """Score predictions, write metrics.json + table.md. Failures are not dropped."""
    from collections import Counter

    preds = []
    lats = {}
    costs = {}
    compile_failed = []
    slither_failed = []
    timed_out = []
    other_failed = []
    status_counts = Counter(r.get("status") for r in raw_rows)
    for rec in raw_rows:
        cid = rec["contract_id"]
        lats[cid] = float(rec.get("latency_s") or 0)
        costs[cid] = float(rec.get("cost_usd") or 0)
        status = rec.get("status") or "unknown"
        if status == "compile_failed":
            compile_failed.append(cid)
        elif status == "slither_failed":
            slither_failed.append(cid)
        elif status == "timeout":
            timed_out.append(cid)
        elif status != "completed":
            other_failed.append(cid)
        for f in rec.get("findings") or []:
            preds.append(Prediction(
                contract_id=cid,
                vuln_class=f.get("vuln_class") or "other",
                lines=tuple(int(x) for x in (f.get("lines") or [])),
                function=f.get("function"),
                detector=f.get("detector"),
            ))

    contract_ids = [m["contract_id"] for m in manifest]
    metrics = score(
        labels, preds,
        contract_ids=contract_ids,
        latencies_s=lats,
        costs=costs,
        compile_failed_ids=compile_failed,
        classes=list(DASP_CLASSES),
    )
    token_est = estimate_tokens(manifest, {r["contract_id"]: r for r in raw_rows}, prices)
    payload = metrics.to_dict()
    payload["run_id"] = run_id
    payload["system"] = system_key
    payload["started_or_written_at"] = _now()
    payload["timezone"] = "America/Detroit"
    payload["pins"] = pins
    payload["token_estimate"] = token_est
    payload["compile_failure_count"] = len(compile_failed)
    payload["compile_failed_ids"] = compile_failed
    payload["slither_failure_count"] = len(slither_failed)
    payload["slither_failed_ids"] = slither_failed
    payload["timeout_count"] = len(timed_out)
    payload["timeout_ids"] = timed_out
    payload["other_failure_count"] = len(other_failed)
    payload["other_failed_ids"] = other_failed
    payload["status_counts"] = dict(status_counts)
    (run_dir / "metrics.json").write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    write_table(payload, run_id=run_id, pins=pins, n_manifest=len(manifest),
                path=run_dir / "table.md", system_name=system_name)
    print(f"wrote {run_dir}")
    print(f"status counts: {payload['status_counts']}")
    print(f"line P/R/F1: {fmt(metrics.line.get('precision'))} / {fmt(metrics.line.get('recall'))} / {fmt(metrics.line.get('f1'))}")
    print(f"compile failures: {len(compile_failed)}")
    print(f"slither tool failures: {len(slither_failed)}")
    print(f"timeouts: {len(timed_out)}")
    return payload


def main() -> int:
    args = parse_args()
    models_cfg = load(ROOT / "config" / "models.yaml")
    prices = load(ROOT / "config" / "prices.yaml")
    pins = json.loads((ROOT / "datasets" / "pins.json").read_text(encoding="utf-8")) if (ROOT / "datasets" / "pins.json").is_file() else {}
    manifest = load_jsonl(args.manifest)
    if args.limit:
        manifest = manifest[: args.limit]
    labels = labels_from_jsonl(args.labels)

    system_key = args.model
    system = (models_cfg.get("systems") or {}).get(system_key)
    if not system:
        raise SystemExit(f"unknown MODEL={system_key!r}; known: {sorted((models_cfg.get('systems') or {}).keys())}")

    if args.table_only and not args.rescore:
        run_dir = args.run_dir
        if not run_dir:
            raise SystemExit("--table-only requires --run-dir")
        metrics = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))
        write_table(metrics, run_id=run_dir.name, pins=pins, n_manifest=len(manifest),
                    path=run_dir / "table.md", system_name=system_key)
        print(f"wrote {run_dir / 'table.md'}")
        return 0

    if args.rescore:
        run_dir = args.run_dir
        if not run_dir:
            raise SystemExit("--rescore requires --run-dir")
        raw_path = run_dir / "raw.jsonl"
        if not raw_path.is_file():
            raise SystemExit(f"missing {raw_path}")
        raw_rows = load_jsonl(raw_path)
        score_run(
            raw_rows, manifest, labels, pins, prices,
            run_dir=run_dir, run_id=args.run_id or run_dir.name,
            system_key=system_key, system_name="Slither only" if system_key == "slither" else system_key,
        )
        return 0

    if system.get("kind") != "slither":
        # Build the provider so the spend-cap and key checks are exercised, then
        # refuse to start a paid/local-LLM sweep in this workstream.
        defaults = models_cfg.get("defaults") or {}
        cap = args.max_spend if args.max_spend is not None else float(defaults.get("max_spend_usd") or 15)
        provider = get_provider(system["provider"], {"defaults": {**defaults, **system}}, prices)
        # Touch the cap with a dummy estimate so a $0 cap would abort immediately.
        try:
            provider.assert_can_spend(0.0, cap, 0.0)
        except SpendCapExceeded as exc:
            raise SystemExit(str(exc))
        if system["provider"] in {"openai", "anthropic"}:
            raise SystemExit(
                f"Refusing to run paid model {system_key!r}. Provider stubs are wired "
                f"(env keys, hard cap ${cap:.2f}) but this workstream does not call paid APIs."
            )
        raise SystemExit(
            f"Refusing to run {system_key!r} here. The local Qwen/Ollama eval must run "
            "on Solana's Mac (Ollama daemon + the exact model tag). "
            "See the README 'Qwen local run' section."
        )

    run_id = args.run_id or datetime.now(DETROIT).strftime("slither-%Y%m%d-%H%M%S")
    run_dir = args.run_dir or (ROOT / "results" / run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    raw_path = run_dir / "raw.jsonl"

    print(f"run {run_id}: slither baseline on {len(manifest)} contracts", flush=True)
    raw_rows = []
    with raw_path.open("w", encoding="utf-8") as fh:
        for i, m in enumerate(manifest, 1):
            src = ROOT / m["path"]
            result = analyze_contract(src, timeout=args.timeout)
            rec = {
                "contract_id": m["contract_id"],
                "source": m["source"],
                "path": m["path"],
                "file_sha256": m["file_sha256"],
                "status": result.status,
                "solc_version": result.solc_version or m.get("solc_version"),
                "solc_path": result.solc_path,
                "latency_s": result.latency_s,
                "error": result.error,
                "slither_status": result.slither_status,
                "n_detectors_raw": result.n_detectors_raw,
                "findings": result.findings,
                "cost_usd": 0.0,
                "input_tokens": 0,
                "output_tokens": 0,
            }
            raw_rows.append(rec)
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            fh.flush()
            if i % 10 == 0 or result.status != "completed":
                print(f"  [{i}/{len(manifest)}] {m['contract_id']} {result.status} "
                      f"findings={len(result.findings)} {result.latency_s:.1f}s "
                      f"{(result.error or '')[:80]}", flush=True)

    score_run(
        raw_rows, manifest, labels, pins, prices,
        run_dir=run_dir, run_id=run_id,
        system_key=system_key, system_name="Slither only",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
