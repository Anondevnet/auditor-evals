"""Pinned dataset commits and sampling constants."""

from __future__ import annotations

# Fixed sampling seed for SolidiFI (stratified) and Wild (unverified-clean).
SAMPLE_SEED = 20261114

# Default-branch tips recorded 2026-11-14 from the GitHub API, then cloned
# and confirmed with `git rev-parse HEAD`.
DATASET_PINS = {
    "smartbugs-curated": {
        "url": "https://github.com/smartbugs/smartbugs-curated.git",
        "commit": "230e649123477eff332742a59a1c7cc6dc286cab",
        "ref": "main",
        "recorded_at": "2026-11-14",
        "license": "Apache-2.0 (contracts keep original licenses)",
    },
    "SolidiFI-benchmark": {
        "url": "https://github.com/smartbugs/SolidiFI-benchmark.git",
        "commit": "4b0573e1b3f7031396de6f48f7f3e7380222ad3a",
        "ref": "master",
        "recorded_at": "2026-11-14",
        "license": "No SPDX; research use, cite Ghaleb & Pattabiraman, ISSTA 2020",
        "upstream": "https://github.com/DependableSystemsLab/SolidiFI-benchmark",
    },
    "smartbugs-wild": {
        "url": "https://github.com/smartbugs/smartbugs-wild.git",
        "commit": "91ec17573d3e0f42cc7d4a6d2883b941901c26e5",
        "ref": "master",
        "recorded_at": "2026-11-14",
        "license": "Apache-2.0",
    },
}

# SHA-256 of key upstream files at the pinned commits (verified after clone).
KEY_FILE_SHA256 = {
    "smartbugs-curated/vulnerabilities.json": None,  # filled after first hash in fetch
}

DASP_CLASSES = (
    "reentrancy",
    "access_control",
    "arithmetic",
    "unchecked_low_level_calls",
    "denial_of_service",
    "bad_randomness",
    "front_running",
    "time_manipulation",
    "short_addresses",
    "other",  # SmartBugs Curated leftover (3 labels); not a DASP-10 class
)

# SolidiFI bug-type folder names -> DASP
SOLIDIFI_TO_DASP = {
    "Re-entrancy": "reentrancy",
    "Timestamp-Dependency": "time_manipulation",
    "Unchecked-Send": "unchecked_low_level_calls",
    "Unhandled-Exceptions": "unchecked_low_level_calls",
    "TOD": "front_running",
    "Overflow-Underflow": "arithmetic",
    "tx.origin": "access_control",
}

# SmartBugs Curated category field is already DASP-ish.
CURATED_TO_DASP = {
    "reentrancy": "reentrancy",
    "access_control": "access_control",
    "arithmetic": "arithmetic",
    "unchecked_low_level_calls": "unchecked_low_level_calls",
    "denial_of_service": "denial_of_service",
    "bad_randomness": "bad_randomness",
    "front_running": "front_running",
    "time_manipulation": "time_manipulation",
    "short_addresses": "short_addresses",
    "other": "other",
}

SOLIDIFI_TYPES = (
    "Overflow-Underflow",
    "Re-entrancy",
    "TOD",
    "Timestamp-Dependency",
    "Unchecked-Send",
    "Unhandled-Exceptions",
    "tx.origin",
)
