from scoring.match import Label, Prediction
from scoring.metrics import aggregate_runs, cost_from_tokens, mean_std, percentile, score


def test_perfect_scores():
    labels = [Label("c", "reentrancy", (10,), "w", "vulnerable")]
    preds = [Prediction("c", "reentrancy", (10,), "w")]
    m = score(labels, preds, contract_ids=["c"], classes=["reentrancy"])
    assert m.line["tp"] == 1 and m.line["fp"] == 0 and m.line["fn"] == 0
    assert m.line["precision"] == 1
    assert m.line["recall"] == 1
    assert m.line["f1"] == 1
    assert m.contract["f1"] == 1


def test_clean_fp_rate():
    labels = [
        Label("good", None, (), None, "clean"),
        Label("bad", None, (), None, "clean"),
        Label("v", "reentrancy", (3,), "f", "vulnerable"),
    ]
    preds = [
        Prediction("good", "reentrancy", (1,), "f"),
        Prediction("v", "reentrancy", (3,), "f"),
    ]
    m = score(labels, preds, contract_ids=["good", "bad", "v"], classes=["reentrancy"])
    assert m.n_clean == 2
    assert m.fp_rate_clean == 0.5
    assert abs(m.findings_per_contract - (2 / 3)) < 1e-9


def test_compile_failures_counted_not_dropped():
    labels = [Label("fail", "reentrancy", (10,), "w", "vulnerable")]
    m = score(labels, [], contract_ids=["fail"], compile_failed_ids=["fail"], classes=["reentrancy"])
    assert m.compile_failures == 1
    assert m.line["fn"] == 1
    assert m.n_contracts == 1
    assert m.findings_per_contract == 0


def test_micro_macro_two_classes():
    labels = [
        Label("a", "reentrancy", (10,), "w", "vulnerable"),
        Label("b", "arithmetic", (20,), "add", "vulnerable"),
    ]
    preds = [
        Prediction("a", "reentrancy", (10,), "w"),
        Prediction("b", "arithmetic", (80,), "other"),
        Prediction("b", "reentrancy", (20,), "add"),
    ]
    m = score(labels, preds, contract_ids=["a", "b"], classes=["reentrancy", "arithmetic"])
    assert m.line["tp"] == 1
    assert m.line["fp"] == 2
    assert m.line["fn"] == 1
    assert m.line["micro"]["precision"] == 1 / 3
    assert "reentrancy" in m.per_class_line
    assert m.line["macro"]["f1"] is not None


def test_latency_percentiles_and_cost():
    labels = [Label("a", "reentrancy", (1,), "f", "vulnerable")]
    preds = [Prediction("a", "reentrancy", (1,), "f")]
    m = score(
        labels, preds, contract_ids=["a"],
        latencies_s={"a": 2.5}, costs={"a": 0.0}, classes=["reentrancy"],
    )
    assert m.latency_p50_s == 2.5
    assert m.latency_p95_s == 2.5
    assert m.cost_total == 0.0
    assert m.cost_per_contract == 0.0


def test_percentile_and_cost_helpers():
    assert percentile([1, 2, 3, 4, 5], 50) == 3
    assert cost_from_tokens(1_000_000, 1_000_000, 2.0, 10.0) == 12.0
    assert cost_from_tokens(6000, 1500, 2.0, 10.0) == (6000 / 1e6) * 2 + (1500 / 1e6) * 10


def test_mean_std_and_aggregate():
    s = mean_std([1.0, 1.0, 1.0])
    assert s["mean"] == 1.0 and s["std"] == 0.0
    agg = aggregate_runs([
        {"line": {"precision": 0.5, "recall": 0.5, "f1": 0.5}, "fp_rate_clean": 0.1,
         "cost_per_contract": 0.01, "latency_p50_s": 1, "latency_p95_s": 2,
         "findings_per_contract": 3, "contract": {"precision": 0.4, "recall": 0.4, "f1": 0.4}},
        {"line": {"precision": 0.7, "recall": 0.7, "f1": 0.7}, "fp_rate_clean": 0.3,
         "cost_per_contract": 0.03, "latency_p50_s": 3, "latency_p95_s": 4,
         "findings_per_contract": 5, "contract": {"precision": 0.6, "recall": 0.6, "f1": 0.6}},
    ])
    assert abs(agg["line_f1"]["mean"] - 0.6) < 1e-9
    assert agg["line_f1"]["n"] == 2
