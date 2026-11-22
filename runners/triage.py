"""Parse a Slither+LLM triage reply and apply confirm/reject decisions."""

from __future__ import annotations

import json
import re
from typing import Any


_THINK = re.compile(r"<think>.*?</think>", re.S | re.I)
_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.M)


def parse_llm_json(text: str) -> dict[str, Any]:
    if not text or not text.strip():
        raise ValueError("empty model output")
    s = _THINK.sub("", text).strip()
    s = _FENCE.sub("", s).strip()
    start, end = s.find("{"), s.rfind("}")
    if start < 0 or end < 0 or end <= start:
        raise ValueError("no JSON object in model output")
    data = json.loads(s[start : end + 1])
    if not isinstance(data, dict):
        raise ValueError("model JSON is not an object")
    return data


def apply_triage(findings: list[dict], parsed: dict) -> list[dict]:
    """Keep slither findings that were not explicitly rejected; append new_findings."""
    rejected: set[int] = set()
    for t in parsed.get("triage") or []:
        if not isinstance(t, dict):
            continue
        if str(t.get("decision") or "").lower() != "reject":
            continue
        idx = t.get("index", t.get("i"))
        if isinstance(idx, int) and 1 <= idx <= len(findings):
            rejected.add(idx - 1)
            continue
        det = t.get("detector")
        if det:
            for j, f in enumerate(findings):
                if f.get("detector") == det and j not in rejected:
                    rejected.add(j)
                    break
    out = [dict(f) for i, f in enumerate(findings) if i not in rejected]
    for nf in parsed.get("new_findings") or []:
        if not isinstance(nf, dict):
            continue
        out.append(
            {
                "vuln_class": nf.get("vuln_class") or "other",
                "detector": "llm_new",
                "title": str(nf.get("reason") or nf.get("title") or "LLM-proposed finding")[:240],
                "function": nf.get("function"),
                "lines": list(nf.get("lines") or []),
                "severity": nf.get("severity") or "",
                "epistemic": "AI_OPINION",
            }
        )
    return out
