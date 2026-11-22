"""Map Slither detector slugs (and auditor playbook classes) to DASP classes.

See docs/slither_dasp_map.md for the human-readable table.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Mapping, Optional

ROOT = Path(__file__).resolve().parent.parent
MAP_PATH = ROOT / "config" / "slither_dasp_map.yaml"

# Playbook class -> default DASP (overridden per-slug when needed).
PLAYBOOK_CLASS_TO_DASP = {
    "reentrancy": "reentrancy",
    "access_control": "access_control",
    "privileged_auth": "access_control",
    "privileged_change": "access_control",
    "delegatecall": "access_control",
    "arbitrary_transfer": "access_control",
    "unchecked_call": "unchecked_low_level_calls",
    "arithmetic": "arithmetic",
    "denial_of_service": "denial_of_service",
    "weak_randomness": "bad_randomness",  # timestamp slug is remapped to time_manipulation
    "logic_error": "other",
    "storage_state_integrity": "other",
    "compiler_language_pitfall": "other",
    "signature_hash_collision": "other",
    "backdoor_obfuscation": "access_control",
    "oracle_staleness": "other",
    "pool_accounting": "arithmetic",
    "erc4626_inflation": "arithmetic",
    "l2_cross_chain": "other",
    "token_interface": "other",
    "missing_events": "other",
    "generic": "other",
    "scam_honeypot": "access_control",
    "known_exploit": "other",
}

# Slug-level overrides / additions. timestamp is time manipulation, not RNG.
SLUG_TO_DASP = {
    "timestamp": "time_manipulation",
    "weak-prng": "bad_randomness",
    "gelato-unprotected-randomness": "bad_randomness",
    "locked-ether": "denial_of_service",
    "calls-loop": "denial_of_service",
    "return-bomb": "denial_of_service",
    "reentrancy-eth": "reentrancy",
    "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy",
    "reentrancy-events": "reentrancy",
    "reentrancy-balance": "reentrancy",
    "reentrancy-unlimited-gas": "reentrancy",
    "tx-origin": "access_control",
    "suicidal": "access_control",
    "unchecked-send": "unchecked_low_level_calls",
    "unchecked-lowlevel": "unchecked_low_level_calls",
    "unchecked-transfer": "unchecked_low_level_calls",
    "unused-return": "unchecked_low_level_calls",
    "arbitrary-send-eth": "access_control",
    "arbitrary-send-erc20": "access_control",
    "controlled-delegatecall": "access_control",
}


def _load_yaml_map() -> dict:
    path = MAP_PATH
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(text) or {}
    except Exception:
        # Minimal YAML subset: we also ship a JSON sibling if PyYAML is missing.
        json_path = path.with_suffix(".json")
        if json_path.is_file():
            data = json.loads(json_path.read_text(encoding="utf-8"))
        else:
            data = {}
    return data


@lru_cache(maxsize=1)
def slug_index() -> dict[str, str]:
    idx = dict(SLUG_TO_DASP)
    # Enrich from auditor playbook when available.
    try:
        from auditor.risk_playbook import load_playbook
        pb = load_playbook()
        for cls, entry in (pb.get("classes") or {}).items():
            dasp = PLAYBOOK_CLASS_TO_DASP.get(cls, "other")
            for slug in entry.get("slugs") or []:
                idx.setdefault(slug, dasp)
    except Exception:
        pass
    data = _load_yaml_map()
    for slug, dasp in (data.get("slugs") or {}).items():
        idx[str(slug)] = str(dasp)
    return idx


def slither_slug_to_dasp(slug: str) -> str:
    slug = (slug or "").strip()
    idx = slug_index()
    if slug in idx:
        return idx[slug]
    if slug.startswith("reentrancy"):
        return "reentrancy"
    return "other"


def finding_to_dasp(finding: Mapping) -> str:
    """Map an auditor finding or raw detector dict to a DASP class."""
    slug = finding.get("check") or finding.get("detector") or finding.get("slug")
    if not slug:
        title = str(finding.get("title") or "")
        # auditor titles are "{slug} in Contract.fn"
        slug = title.split()[0] if title else ""
        if "detector:" in str(finding.get("description") or ""):
            import re
            m = re.search(r"detector:\s*([a-z0-9-]+)", str(finding["description"]), re.I)
            if m:
                slug = m.group(1)
    if slug:
        return slither_slug_to_dasp(str(slug))
    # last resort: auditor playbook class names
    cls = str(finding.get("category") or finding.get("vulnerability_class") or "")
    return PLAYBOOK_CLASS_TO_DASP.get(cls, "other")
