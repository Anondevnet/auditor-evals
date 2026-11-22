from scoring.match import (
    Label,
    Prediction,
    clean_contract_ids,
    is_line_match,
    lines_close,
    match_contract_level,
    match_line_level,
    same_function,
)


def L(cid="c1", cls="reentrancy", lines=(10,), fn="withdraw", label="vulnerable"):
    return Label(contract_id=cid, vuln_class=cls, lines=tuple(lines), function=fn, label=label)


def P(cid="c1", cls="reentrancy", lines=(11,), fn="withdraw", det="reentrancy-eth"):
    return Prediction(contract_id=cid, vuln_class=cls, lines=tuple(lines), function=fn, detector=det)


def test_lines_close_window():
    assert lines_close([10], [13], 3)
    assert lines_close([10], [7], 3)
    assert not lines_close([10], [14], 3)
    assert not lines_close([10], [], 3)
    assert not lines_close([], [10], 3)


def test_same_function():
    assert same_function("withdraw", "withdraw")
    assert not same_function("withdraw", "deposit")
    assert not same_function(None, "withdraw")
    assert not same_function("withdraw", None)


def test_match_by_line_same_class():
    assert is_line_match(L(lines=(20,), fn=None), P(lines=(23,), fn=None))
    assert not is_line_match(L(lines=(20,), fn=None), P(lines=(30,), fn=None))


def test_match_by_function_despite_far_lines():
    assert is_line_match(L(lines=(20,), fn="withdraw"), P(lines=(200,), fn="withdraw"))
    assert not is_line_match(L(lines=(20,), fn="withdraw"), P(lines=(200,), fn="deposit"))


def test_class_mismatch_is_not_tp():
    assert not is_line_match(L(cls="reentrancy"), P(cls="arithmetic"))


def test_greedy_one_to_one():
    gold = [L(lines=(10,), fn="a"), L(lines=(40,), fn="b")]
    pred = [P(lines=(10,), fn="a"), P(lines=(11,), fn="a"), P(lines=(41,), fn="b")]
    res = match_line_level(gold, pred)
    assert res.tp == 2
    assert res.fp == 1
    assert res.fn == 0


def test_false_negative_and_positive():
    res = match_line_level([L(lines=(10,), fn="a")], [P(cls="arithmetic", lines=(10,), fn="a")])
    assert res.tp == 0
    assert res.fp == 1
    assert res.fn == 1


def test_clean_labels_are_not_gold_at_line_level():
    res = match_line_level(
        [L(cls=None, lines=(), fn=None, label="clean")],
        [P(lines=(1,), fn="f")],
    )
    assert res.tp == 0
    assert res.fn == 0
    assert res.fp == 1


def test_contract_level_per_class():
    gold = [L(cid="a", cls="reentrancy"), L(cid="b", cls="arithmetic")]
    pred = [P(cid="a", cls="reentrancy"), P(cid="a", cls="arithmetic")]
    out = match_contract_level(gold, pred, classes=["reentrancy", "arithmetic"])
    tags = {(o.contract_id, o.vuln_class): o.tag for o in out}
    assert tags[("a", "reentrancy")] == "tp"
    assert tags[("a", "arithmetic")] == "fp"
    assert tags[("b", "arithmetic")] == "fn"
    assert tags[("b", "reentrancy")] == "tn"


def test_clean_contract_ids():
    labels = [
        L(cid="clean1", cls=None, lines=(), fn=None, label="clean"),
        L(cid="vuln1", cls="reentrancy"),
    ]
    assert clean_contract_ids(labels) == {"clean1"}
