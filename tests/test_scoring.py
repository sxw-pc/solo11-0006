from __future__ import annotations
from shellhunt.engine.entropy import EntropyReport, analyze_entropy
from shellhunt.engine.features import FeatureReport, FeatureSignal, analyze_features
from shellhunt.engine.rules import RuleHit
from shellhunt.engine.scoring import score_file
THRESHOLDS = {"suspicious": 20, "malicious": 60}
UNCAPPED = {"per_rule_cap": 100, "rule_total_cap": 100}
def hit(rule_id: str = "TEST-001", weight: int = 10, line: int = 1) -> RuleHit:
    return RuleHit(rule_id, f"Rule {rule_id}", "high", weight, line, "evidence", "regex")
def empty_features() -> FeatureReport:
    return analyze_features("")
def test_rule_weights_add_together():
    result = score_file(
        [hit("A-1", 10), hit("B-2", 15)], empty_features(), analyze_entropy("")
    )
    assert result.score == 25
    assert result.totals["rules"] == 25
    assert result.verdict == "suspicious"
def test_repeated_rule_only_counts_once():
    result = score_file(
        [hit("SAME", 15), hit("SAME", 15, line=3), hit("SAME", 15, line=4)],
        empty_features(),
        analyze_entropy(""),
    )
    assert result.score == 15
    assert len([s for s in result.signals if s["kind"] == "rule"]) == 1
def test_per_rule_cap_is_applied():
    result = score_file([hit("BIG", 100)], empty_features(), analyze_entropy(""))
    assert result.totals["rules"] == 40
    assert result.score == 40
    assert [s for s in result.signals if s.get("rule_id") == "BIG"][0]["capped"] is True
def test_rule_total_cap_is_applied():
    result = score_file(
        [hit("A-1", 30), hit("B-2", 30), hit("C-3", 30)],
        empty_features(),
        analyze_entropy(""),
    )
    assert result.totals["rules"] == 70
    assert sum(s["points"] for s in result.signals if s["kind"] == "rule") == 70
def test_feature_weights_and_total_cap():
    features = FeatureReport(
        dangerous_functions={},
        signals={
            "direct_input": FeatureSignal("direct_input", 1.0, [1]),
            "dynamic_call": FeatureSignal("dynamic_call", 1.0, [1]),
            "dangerous_calls": FeatureSignal("dangerous_calls", 1.0, [1]),
            "obfuscation": FeatureSignal("obfuscation", 1.0, [1]),
        },
        superglobal_lines=[1],
        token_count=10,
    )
    result = score_file([], features, analyze_entropy(""))
    assert result.totals["features"] == 40
    assert sum(s["points"] for s in result.signals if s["kind"] == "feature") == 40
def test_single_feature_uses_its_weight():
    features = FeatureReport(
        {}, {"direct_input": FeatureSignal("direct_input", 1.0, [7])}, [7], 3
    )
    result = score_file([], features, analyze_entropy(""))
    assert result.totals["features"] == 22
    signal = [s for s in result.signals if s["kind"] == "feature"][0]
    assert signal["points"] == 22 and signal["lines"] == [7]
def test_entropy_signal_and_cap():
    report = EntropyReport(0, 0, 0, 10, [], 5, ["base64_decode", "gzinflate"])
    result = score_file([], empty_features(), report)
    assert result.totals["entropy"] == 15
    assert sum(s["points"] for s in result.signals if s["kind"] == "entropy") == 15
def test_entropy_below_cap():
    report = EntropyReport(0, 0, 0, 2, [], 2, ["base64_decode", "gzinflate"])
    result = score_file([], empty_features(), report)
    assert result.totals["entropy"] == 12
def test_baseline_scoring():
    new_result = score_file(
        [], empty_features(), analyze_entropy(""), baseline_status="new"
    )
    modified_result = score_file(
        [], empty_features(), analyze_entropy(""), baseline_status="modified"
    )
    assert new_result.totals["baseline"] == 8
    assert modified_result.totals["baseline"] == 12
def test_threshold_boundaries():
    assert score_file(
        [], empty_features(), analyze_entropy(""), thresholds=THRESHOLDS,
        scoring_config=UNCAPPED,
    ).score == 0
    for weight, expected in ((19, "clean"), (20, "suspicious"), (59, "suspicious"), (60, "malicious")):
        result = score_file(
            [hit("B-1", weight)],
            empty_features(),
            analyze_entropy(""),
            thresholds=THRESHOLDS,
            scoring_config=UNCAPPED,
        )
        assert result.score == weight
        assert result.verdict == expected
def test_hash_match_overrides_everything():
    rule = hit("A-1", 30)
    result = score_file(
        [rule],
        empty_features(),
        analyze_entropy(""),
        known_bad_label="fixtures/corpus/malicious/synthetic.phps",
        thresholds={"suspicious": 99, "malicious": 100},
    )
    assert result.score == 100
    assert result.verdict == "malicious"
    assert result.hash_override is True
    assert result.signals[0]["kind"] == "hash"
    assert rule.points == 30
def test_allowlist_overrides_rules_and_known_bad_wins():
    allowed = score_file(
        [hit("A-1", 30)],
        empty_features(),
        analyze_entropy(""),
        allowlisted_label="reviewed benign file",
    )
    assert allowed.score == 0
    assert allowed.verdict == "clean"
    assert allowed.signals[0]["kind"] == "allowlist"
    known = score_file(
        [hit("A-1", 30)],
        empty_features(),
        analyze_entropy(""),
        known_bad_label="known synthetic sample",
        allowlisted_label="reviewed benign file",
    )
    assert known.score == 100
    assert known.verdict == "malicious"
    assert known.signals[0]["kind"] == "hash"
def test_signals_are_explainable():
    result = score_file([hit("A-1", 25, line=9)], empty_features(), analyze_entropy(""))
    rule_signal = [s for s in result.signals if s["kind"] == "rule"][0]
    assert rule_signal["rule_id"] == "A-1"
    assert rule_signal["line"] == 9
    assert rule_signal["points"] == 25
    assert "matched at line 9" in rule_signal["detail"]
