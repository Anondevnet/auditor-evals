"""Slither + LLM triage prompt used for token estimates (and later LLM runs)."""

from __future__ import annotations

from typing import Sequence

SYSTEM = (
    "You are triaging a smart-contract static-analysis report. "
    "For each Slither finding, decide confirm or reject. You may propose "
    "additional findings. Your output is AI_OPINION only, never FACT. "
    "Reply with JSON: {\"triage\": [{\"detector\": str, \"decision\": "
    "\"confirm\"|\"reject\", \"reason\": str}], \"new_findings\": "
    "[{\"vuln_class\": str, \"function\": str|null, \"lines\": [int], "
    "\"reason\": str}]}."
)


def build_user_prompt(contract_id: str, source: str, findings: Sequence[dict], solc_version=None) -> str:
    lines = [
        f"Contract id: {contract_id}",
        f"solc: {solc_version or 'unknown'}",
        f"Slither findings: {len(findings)}",
        "",
        "# Findings",
    ]
    if not findings:
        lines.append("(none)")
    else:
        for i, f in enumerate(findings, 1):
            loc = ",".join(str(x) for x in (f.get("lines") or [])[:8]) or "?"
            lines.append(
                f"{i}. class={f.get('vuln_class')} detector={f.get('detector')} "
                f"fn={f.get('function')} lines=[{loc}] severity={f.get('severity')}"
            )
            if f.get("title"):
                lines.append(f"   title: {f['title']}")
    lines.extend(["", "# Source", "```solidity", source.rstrip(), "```"])
    return "\n".join(lines)
