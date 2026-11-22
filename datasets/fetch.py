#!/usr/bin/env python3
"""Fetch pinned public datasets, verify SHAs, and freeze manifest.jsonl.

Usage: python datasets/fetch.py

Clones land in datasets/raw/ (gitignored). Selected contracts are copied to
datasets/files/ and described in datasets/manifest.jsonl. Labels are written
under labels/ via labels/convert.py.

This script never talks to a paid API.
"""

from __future__ import annotations

import hashlib
import json
import random
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evalharness.constants import (
    DATASET_PINS,
    SAMPLE_SEED,
    SOLIDIFI_TO_DASP,
    SOLIDIFI_TYPES,
)
from evalharness.source import pragma_constraint, read_text, sha256_file
from evalharness.solcutil import solc_binary, try_compile, version_for_source
from labels.convert import convert_all

RAW = ROOT / "datasets" / "raw"
FILES = ROOT / "datasets" / "files"
MANIFEST = ROOT / "datasets" / "manifest.jsonl"
PINS_OUT = ROOT / "datasets" / "pins.json"
N_SOLIDIFI = 50
N_WILD = 50
WILD_COMPILE_ATTEMPTS = 400


def _run(argv, cwd=None, check=True):
    return subprocess.run(argv, cwd=cwd, check=check, text=True, capture_output=True)


def clone_pinned(name: str, dest: Path) -> str:
    pin = DATASET_PINS[name]
    url, sha = pin["url"], pin["commit"]
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not (dest / ".git").is_dir():
        print(f"cloning {url} -> {dest}")
        subprocess.run(["git", "clone", "--depth", "1", url, str(dest)], check=True)
    head = _run(["git", "rev-parse", "HEAD"], cwd=dest).stdout.strip()
    if head != sha:
        print(f"  HEAD {head} != pin {sha}; fetching pin")
        subprocess.run(["git", "fetch", "--depth", "1", "origin", sha], cwd=dest, check=True)
        subprocess.run(["git", "checkout", "--force", sha], cwd=dest, check=True)
        head = _run(["git", "rev-parse", "HEAD"], cwd=dest).stdout.strip()
    if head != sha:
        raise SystemExit(f"failed to check out pinned commit {sha} for {name} (got {head})")
    print(f"  {name} @ {head}")
    return head


def verify_key_files(repo: Path, relative_paths: list[str]) -> dict[str, str]:
    hashes = {}
    for rel in relative_paths:
        p = repo / rel
        if not p.is_file():
            raise SystemExit(f"missing expected file {p}")
        hashes[rel] = sha256_file(p)
        print(f"  sha256 {rel} = {hashes[rel]}")
    return hashes


def _copy_selected(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)


def _manifest_row(*, contract_id, source, path, src_file, solc_version, pragma, extra=None):
    row = {
        "contract_id": contract_id,
        "source": source,
        "path": path,
        "file_sha256": sha256_file(src_file),
        "solc_version": solc_version,
        "pragma": pragma,
    }
    if extra:
        row.update(extra)
    return row


def build_curated(raw: Path) -> list[dict]:
    vulns = json.loads((raw / "vulnerabilities.json").read_text(encoding="utf-8"))
    if len(vulns) != 143:
        print(f"warning: expected 143 curated entries, got {len(vulns)}")
    rows = []
    for entry in vulns:
        rel = entry["path"]  # e.g. dataset/reentrancy/foo.sol
        src = raw / rel
        if not src.is_file():
            raise SystemExit(f"curated file missing: {src}")
        dest_rel = f"datasets/files/smartbugs-curated/{Path(rel).as_posix().split('dataset/', 1)[-1]}"
        dest = ROOT / dest_rel
        _copy_selected(src, dest)
        text = read_text(dest)
        pragma = pragma_constraint(text) or entry.get("pragma")
        version = version_for_source(text)
        cid = "curated/" + Path(rel).as_posix().split("dataset/", 1)[-1]
        rows.append(_manifest_row(
            contract_id=cid,
            source="smartbugs-curated",
            path=dest_rel,
            src_file=dest,
            solc_version=version,
            pragma=pragma,
            extra={"upstream_path": rel, "name": entry.get("name")},
        ))
    return rows


def _stratified_counts(n: int, types: tuple[str, ...]) -> dict[str, int]:
    base, rem = divmod(n, len(types))
    # Earlier types (alphabetical, already sorted in SOLIDIFI_TYPES) get the remainder.
    return {t: base + (1 if i < rem else 0) for i, t in enumerate(types)}


def build_solidifi(raw: Path, rng: random.Random) -> list[dict]:
    counts = _stratified_counts(N_SOLIDIFI, SOLIDIFI_TYPES)
    print("  solidifi stratified counts:", counts)
    rows = []
    for bug_type in SOLIDIFI_TYPES:
        folder = raw / "buggy_contracts" / bug_type
        sols = sorted(folder.glob("buggy_*.sol"), key=lambda p: int(p.stem.split("_")[1]))
        if not sols:
            raise SystemExit(f"no buggy_*.sol in {folder}")
        want = counts[bug_type]
        # Prefer contracts that compile with an available solc, but keep
        # stratification exact: if fewer than `want` compile, fill from the rest.
        indexed = []
        for p in sols:
            idx = int(p.stem.split("_")[1])
            log = folder / f"BugLog_{idx}.csv"
            if not log.is_file():
                continue
            indexed.append((idx, p, log))
        rng.shuffle(indexed)
        chosen: list = []
        fallback: list = []
        for idx, p, log in indexed:
            text = read_text(p)
            ver = version_for_source(text)
            ok = False
            if ver:
                try:
                    binp = solc_binary(ver, allow_install=False)
                    ok, _ = try_compile(p, binp, timeout=10)
                except Exception:
                    ok = False
            if ok:
                chosen.append((idx, p, log, ver, pragma_constraint(text)))
            else:
                fallback.append((idx, p, log, ver, pragma_constraint(text)))
            if len(chosen) >= want:
                break
        if len(chosen) < want:
            chosen.extend(fallback[: want - len(chosen)])
        chosen = chosen[:want]
        if len(chosen) < want:
            raise SystemExit(f"not enough SolidiFI contracts for {bug_type}: {len(chosen)} < {want}")
        # stable order by index after selection
        chosen.sort(key=lambda t: t[0])
        for idx, p, log, ver, pragma in chosen:
            dest_rel = f"datasets/files/solidifi/{bug_type}/buggy_{idx}.sol"
            dest = ROOT / dest_rel
            _copy_selected(p, dest)
            # also copy the bug log next to it for converters that want a local copy
            log_dest = dest.with_name(f"BugLog_{idx}.csv")
            _copy_selected(log, log_dest)
            cid = f"solidifi/{bug_type}/buggy_{idx}.sol"
            rows.append(_manifest_row(
                contract_id=cid,
                source="solidifi",
                path=dest_rel,
                src_file=dest,
                solc_version=ver or version_for_source(read_text(dest)),
                pragma=pragma or pragma_constraint(read_text(dest)),
                extra={"bug_type": bug_type, "solidifi_index": idx, "dasp_class": SOLIDIFI_TO_DASP[bug_type]},
            ))
    return rows


def build_wild(raw: Path, rng: random.Random) -> list[dict]:
    contracts = raw / "contracts"
    all_sols = sorted(contracts.glob("*.sol"))
    if len(all_sols) < N_WILD:
        raise SystemExit(f"wild has only {len(all_sols)} contracts")
    order = list(all_sols)
    rng.shuffle(order)
    selected = []
    attempts = 0
    for p in order:
        if len(selected) >= N_WILD:
            break
        if attempts >= WILD_COMPILE_ATTEMPTS and len(selected) < N_WILD:
            # After the compile budget, keep scanning for pragma-compatible
            # files without compiling, then any leftover.
            break
        text = read_text(p)
        ver = version_for_source(text)
        if not ver:
            continue
        try:
            binp = solc_binary(ver, allow_install=False)
        except Exception:
            continue
        attempts += 1
        ok, err = try_compile(p, binp, timeout=8)
        if ok:
            selected.append((p, ver, pragma_constraint(text), True))
            if len(selected) % 10 == 0:
                print(f"  wild compiled {len(selected)}/{N_WILD} (attempts={attempts})")
    if len(selected) < N_WILD:
        print(f"  only {len(selected)} wild contracts compiled in {attempts} attempts; filling")
        have = {p.resolve() for p, *_ in selected}
        for p in order:
            if len(selected) >= N_WILD:
                break
            if p.resolve() in have:
                continue
            text = read_text(p)
            ver = version_for_source(text)
            if ver:
                selected.append((p, ver, pragma_constraint(text), False))
        for p in order:
            if len(selected) >= N_WILD:
                break
            if p.resolve() in have or any(s[0].resolve() == p.resolve() for s in selected):
                continue
            text = read_text(p)
            selected.append((p, version_for_source(text), pragma_constraint(text), False))
    selected = selected[:N_WILD]
    rows = []
    n_compiled = sum(1 for *_, ok in selected if ok)
    print(f"  wild selected {len(selected)} (compile-verified {n_compiled})")
    for p, ver, pragma, compiled in selected:
        dest_rel = f"datasets/files/smartbugs-wild/{p.name}"
        dest = ROOT / dest_rel
        _copy_selected(p, dest)
        cid = f"wild/{p.name}"
        row = _manifest_row(
            contract_id=cid,
            source="smartbugs-wild",
            path=dest_rel,
            src_file=dest,
            solc_version=ver,
            pragma=pragma,
            extra={"split": "unverified-clean", "compile_verified_at_sample": compiled,
                    "upstream_path": f"contracts/{p.name}"},
        )
        rows.append(row)
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> int:
    rng = random.Random(SAMPLE_SEED)
    commits = {}
    key_hashes = {}
    for name in ("smartbugs-curated", "SolidiFI-benchmark", "smartbugs-wild"):
        dest = RAW / name
        commits[name] = clone_pinned(name, dest)
    key_hashes["smartbugs-curated"] = verify_key_files(
        RAW / "smartbugs-curated", ["vulnerabilities.json", "versions.csv", "LICENSE"]
    )
    key_hashes["SolidiFI-benchmark"] = verify_key_files(
        RAW / "SolidiFI-benchmark", ["LICENSE", "README.md"]
    )
    key_hashes["smartbugs-wild"] = verify_key_files(
        RAW / "smartbugs-wild", ["LICENSE", "README.md"]
    )

    if FILES.exists():
        shutil.rmtree(FILES)
    FILES.mkdir(parents=True)

    print("building curated set (all 143)...")
    curated = build_curated(RAW / "smartbugs-curated")
    print(f"  curated={len(curated)}")
    print("building SolidiFI stratified sample...")
    solidifi = build_solidifi(RAW / "SolidiFI-benchmark", rng)
    print(f"  solidifi={len(solidifi)}")
    print("building Wild unverified-clean sample (prefer compile-success)...")
    wild = build_wild(RAW / "smartbugs-wild", rng)
    print(f"  wild={len(wild)}")

    manifest = curated + solidifi + wild
    write_jsonl(MANIFEST, manifest)
    manifest_sha = hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
    pins = {
        "sample_seed": SAMPLE_SEED,
        "recorded_at": "2026-11-14",
        "commits": {k: {"url": DATASET_PINS[k]["url"], "commit": commits[k], **{kk: vv for kk, vv in DATASET_PINS[k].items() if kk not in ("url", "commit")}} for k in commits},
        "key_file_sha256": key_hashes,
        "manifest": {
            "path": "datasets/manifest.jsonl",
            "sha256": manifest_sha,
            "counts": {
                "smartbugs-curated": len(curated),
                "solidifi": len(solidifi),
                "smartbugs-wild": len(wild),
                "total": len(manifest),
            },
        },
    }
    PINS_OUT.write_text(json.dumps(pins, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {MANIFEST} sha256={manifest_sha} n={len(manifest)}")

    counts = convert_all(MANIFEST, RAW, ROOT / "labels")
    print("labels:", counts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
