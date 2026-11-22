#!/usr/bin/env python3
"""Convert upstream label files into labels/*.jsonl using the eval schema."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Iterable, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evalharness.constants import CURATED_TO_DASP, SOLIDIFI_TO_DASP
from evalharness.source import functions_for_lines, pragma_constraint, read_text, sha256_file
from evalharness.solcutil import version_for_source


def _row(**kwargs) -> dict:
    required = (
        "contract_id", "source", "file_sha256", "solc_version", "label",
        "vuln_class", "lines", "function", "provenance", "label_confidence",
    )
    out = {k: kwargs.get(k) for k in required}
    if "pragma" in kwargs:
        out["pragma"] = kwargs["pragma"]
    return out


def _solc_meta(path: Path) -> tuple[Optional[str], Optional[str]]:
    text = read_text(path)
    pragma = pragma_constraint(text)
    version = version_for_source(text)
    return pragma, version


def convert_curated(manifest_rows: list[dict], raw_root: Path) -> list[dict]:
    vulns = json.loads((raw_root / "vulnerabilities.json").read_text(encoding="utf-8"))
    by_rel = {e["path"]: e for e in vulns}
    rows = []
    for m in manifest_rows:
        if m["source"] != "smartbugs-curated":
            continue
        entry = by_rel.get(m.get("upstream_path") or "")
        if entry is None:
            # try matching by file name
            for e in vulns:
                if Path(e["path"]).name == Path(m["path"]).name and Path(e["path"]).as_posix() in m.get("upstream_path", m["path"]):
                    entry = e
                    break
        if entry is None:
            raise SystemExit(f"no vulnerabilities.json entry for {m['contract_id']}")
        dest = ROOT / m["path"]
        text = read_text(dest)
        for v in entry.get("vulnerabilities") or []:
            lines = [int(x) for x in (v.get("lines") or []) if int(x) > 0]
            cat = CURATED_TO_DASP.get(v.get("category"), "other")
            fn = functions_for_lines(text, lines)
            rows.append(_row(
                contract_id=m["contract_id"],
                source="smartbugs-curated",
                file_sha256=m["file_sha256"],
                solc_version=m.get("solc_version"),
                pragma=m.get("pragma"),
                label="vulnerable",
                vuln_class=cat,
                lines=lines,
                function=fn,
                provenance=f"smartbugs-curated vulnerabilities.json category={v.get('category')}",
                label_confidence="dataset",
            ))
    return rows


def _read_buglog(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        return list(reader)


def convert_solidifi(manifest_rows: list[dict], raw_root: Path) -> list[dict]:
    rows = []
    for m in manifest_rows:
        if m["source"] != "solidifi":
            continue
        bug_type = m["bug_type"]
        idx = m["solidifi_index"]
        log_path = raw_root / "buggy_contracts" / bug_type / f"BugLog_{idx}.csv"
        if not log_path.is_file():
            raise SystemExit(f"missing BugLog for {m['contract_id']}: {log_path}")
        dest = ROOT / m["path"]
        text = read_text(dest)
        dasp = SOLIDIFI_TO_DASP[bug_type]
        for rec in _read_buglog(log_path):
            loc = int(rec["loc"])
            length = int(rec.get("length") or 1)
            lines = list(range(loc, loc + max(length, 1)))
            fn = functions_for_lines(text, lines)
            rows.append(_row(
                contract_id=m["contract_id"],
                source="solidifi",
                file_sha256=m["file_sha256"],
                solc_version=m.get("solc_version"),
                pragma=m.get("pragma"),
                label="vulnerable",
                vuln_class=dasp,
                lines=lines,
                function=fn,
                provenance=f"SolidiFI BugLog_{idx}.csv type={rec.get('bug type') or bug_type} approach={rec.get('approach')}",
                label_confidence="dataset",
            ))
    return rows


def convert_wild(manifest_rows: list[dict]) -> list[dict]:
    rows = []
    for m in manifest_rows:
        if m["source"] != "smartbugs-wild":
            continue
        rows.append(_row(
            contract_id=m["contract_id"],
            source="smartbugs-wild",
            file_sha256=m["file_sha256"],
            solc_version=m.get("solc_version"),
            pragma=m.get("pragma"),
            label="clean",
            vuln_class=None,
            lines=[],
            function=None,
            provenance="unverified-clean sample from SmartBugs Wild (not audited; presumed negative)",
            label_confidence="dataset",
        ))
    return rows


def write_jsonl(path: Path, rows: Iterable[dict]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            n += 1
    return n


def convert_all(manifest_path: Path, raw_dir: Path, out_dir: Path) -> dict:
    manifest = [json.loads(l) for l in manifest_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    curated = convert_curated(manifest, raw_dir / "smartbugs-curated")
    solidifi = convert_solidifi(manifest, raw_dir / "SolidiFI-benchmark")
    wild = convert_wild(manifest)
    counts = {
        "curated": write_jsonl(out_dir / "curated.jsonl", curated),
        "solidifi": write_jsonl(out_dir / "solidifi.jsonl", solidifi),
        "wild": write_jsonl(out_dir / "wild.jsonl", wild),
    }
    counts["all"] = write_jsonl(out_dir / "all.jsonl", curated + solidifi + wild)
    return counts
