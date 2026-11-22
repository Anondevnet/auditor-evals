"""Match predicted findings to gold labels.

A true positive is the same DASP class and either:
  * any predicted line within ±WINDOW of any gold line, or
  * the same function name (when both sides name one).

Each gold label and each prediction is used at most once (greedy, longest
overlap first). Report both line-level (this matching) and contract-level
(any finding of that class on that contract) results.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional, Sequence

DEFAULT_WINDOW = 3


@dataclass(frozen=True)
class Label:
    contract_id: str
    vuln_class: Optional[str]
    lines: tuple[int, ...] = ()
    function: Optional[str] = None
    label: str = "vulnerable"  # vulnerable | clean


@dataclass(frozen=True)
class Prediction:
    contract_id: str
    vuln_class: str
    lines: tuple[int, ...] = ()
    function: Optional[str] = None
    detector: Optional[str] = None


@dataclass
class MatchResult:
    true_positives: list[tuple[Label, Prediction]] = field(default_factory=list)
    false_positives: list[Prediction] = field(default_factory=list)
    false_negatives: list[Label] = field(default_factory=list)

    @property
    def tp(self) -> int:
        return len(self.true_positives)

    @property
    def fp(self) -> int:
        return len(self.false_positives)

    @property
    def fn(self) -> int:
        return len(self.false_negatives)


def lines_close(gold: Sequence[int], pred: Sequence[int], window: int = DEFAULT_WINDOW) -> bool:
    if not gold or not pred:
        return False
    for g in gold:
        for p in pred:
            if abs(int(g) - int(p)) <= window:
                return True
    return False


def same_function(gold_fn: Optional[str], pred_fn: Optional[str]) -> bool:
    if not gold_fn or not pred_fn:
        return False
    return gold_fn.strip() == pred_fn.strip()


def is_line_match(gold: Label, pred: Prediction, window: int = DEFAULT_WINDOW) -> bool:
    if gold.label != "vulnerable":
        return False
    if (gold.vuln_class or "") != (pred.vuln_class or ""):
        return False
    if gold.contract_id != pred.contract_id:
        return False
    return lines_close(gold.lines, pred.lines, window) or same_function(gold.function, pred.function)


def _overlap_score(gold: Label, pred: Prediction, window: int) -> int:
    """Higher is better; used to prefer tighter line overlaps in greedy matching."""
    if not is_line_match(gold, pred, window):
        return -1
    score = 0
    if same_function(gold.function, pred.function):
        score += 100
    if gold.lines and pred.lines:
        best = min(abs(int(g) - int(p)) for g in gold.lines for p in pred.lines)
        score += max(0, (window + 1) - best)
    return score


def match_line_level(
    labels: Iterable[Label],
    preds: Iterable[Prediction],
    window: int = DEFAULT_WINDOW,
) -> MatchResult:
    """Greedy one-to-one matching at line/function granularity."""
    golds = [g for g in labels if g.label == "vulnerable" and g.vuln_class]
    predictions = list(preds)
    used_g: set[int] = set()
    used_p: set[int] = set()
    pairs: list[tuple[int, int, int]] = []  # score, gi, pi
    for gi, g in enumerate(golds):
        for pi, p in enumerate(predictions):
            s = _overlap_score(g, p, window)
            if s >= 0:
                pairs.append((s, gi, pi))
    pairs.sort(key=lambda t: (-t[0], t[1], t[2]))
    tps: list[tuple[Label, Prediction]] = []
    for _, gi, pi in pairs:
        if gi in used_g or pi in used_p:
            continue
        used_g.add(gi)
        used_p.add(pi)
        tps.append((golds[gi], predictions[pi]))
    fps = [p for pi, p in enumerate(predictions) if pi not in used_p]
    fns = [g for gi, g in enumerate(golds) if gi not in used_g]
    return MatchResult(true_positives=tps, false_positives=fps, false_negatives=fns)


@dataclass
class ContractClassOutcome:
    contract_id: str
    vuln_class: str
    gold: bool
    predicted: bool

    @property
    def tag(self) -> str:
        if self.gold and self.predicted:
            return "tp"
        if self.predicted and not self.gold:
            return "fp"
        if self.gold and not self.predicted:
            return "fn"
        return "tn"


def match_contract_level(
    labels: Iterable[Label],
    preds: Iterable[Prediction],
    classes: Optional[Sequence[str]] = None,
) -> list[ContractClassOutcome]:
    """Per (contract, class): gold if any vulnerable label of that class, pred if any finding."""
    labels = list(labels)
    preds = list(preds)
    contract_ids = sorted({* (l.contract_id for l in labels), * (p.contract_id for p in preds)})
    if classes is None:
        classes = sorted(
            {l.vuln_class for l in labels if l.vuln_class}
            | {p.vuln_class for p in preds if p.vuln_class}
        )
    gold_map: dict[tuple[str, str], bool] = {}
    pred_map: dict[tuple[str, str], bool] = {}
    for l in labels:
        if l.label == "vulnerable" and l.vuln_class:
            gold_map[(l.contract_id, l.vuln_class)] = True
    for p in preds:
        if p.vuln_class:
            pred_map[(p.contract_id, p.vuln_class)] = True
    out = []
    for cid in contract_ids:
        for cls in classes:
            out.append(
                ContractClassOutcome(
                    contract_id=cid,
                    vuln_class=cls,
                    gold=bool(gold_map.get((cid, cls))),
                    predicted=bool(pred_map.get((cid, cls))),
                )
            )
    return out


def clean_contract_ids(labels: Iterable[Label]) -> set[str]:
    """Contracts whose only labels are clean (no vulnerable rows)."""
    by: dict[str, set[str]] = {}
    for l in labels:
        by.setdefault(l.contract_id, set()).add(l.label)
    return {cid for cid, labs in by.items() if labs == {"clean"}}
