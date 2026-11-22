from runners.triage import apply_triage, parse_llm_json


def test_parse_strips_fences_and_think_tags():
    raw = """<think>ignore me</think>
```json
{"triage": [{"detector": "reentrancy-eth", "decision": "reject", "reason": "no"}], "new_findings": []}
```
"""
    data = parse_llm_json(raw)
    assert data["triage"][0]["decision"] == "reject"


def test_apply_triage_drops_rejected_and_tags_new():
    findings = [
        {"vuln_class": "reentrancy", "detector": "reentrancy-eth", "function": "withdraw", "lines": [10]},
        {"vuln_class": "access_control", "detector": "arbitrary-send-eth", "function": "setOwner", "lines": [4]},
    ]
    parsed = {
        "triage": [
            {"detector": "reentrancy-eth", "decision": "reject", "reason": "fp"},
            {"detector": "arbitrary-send-eth", "decision": "confirm", "reason": "ok"},
        ],
        "new_findings": [
            {"vuln_class": "access_control", "function": "init", "lines": [2], "reason": "missing onlyOwner"}
        ],
    }
    out = apply_triage(findings, parsed)
    dets = [f["detector"] for f in out]
    assert "reentrancy-eth" not in dets
    assert "arbitrary-send-eth" in dets
    new = [f for f in out if f["detector"] == "llm_new"]
    assert len(new) == 1
    assert new[0]["epistemic"] == "AI_OPINION"
    assert new[0]["vuln_class"] == "access_control"
