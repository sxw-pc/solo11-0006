from __future__ import annotations
from pathlib import Path
import pytest
from shellhunt.engine.rules import (
    RuleError,
    compact_snippet,
    load_rule_file,
    load_ruleset,
)
RULES_DIR = Path(__file__).resolve().parent.parent / "shellhunt" / "ruleset"
def rule_yaml(rule_id: str = "CUSTOM-001", pattern: str = "needle") -> str:
    return f"""rules:
  - id: {rule_id}
    name: Custom marker
    severity: high
    weight: 21
    match: regex
    pattern: '{pattern}'
    description: A custom regression rule.
    remediation: Remove the marker.
"""
def test_builtin_rules_cover_all_match_types(ruleset):
    assert len(ruleset) >= 25
    assert {rule.match for rule in ruleset.rules} == {
        "regex",
        "literal",
        "token_seq",
        "multiline_regex",
    }
    ids = [rule.id for rule in ruleset.rules]
    assert len(ids) == len(set(ids))
def test_regex_positive_and_negative(ruleset):
    positive = ruleset.match("<?php EVAL ( /* $_POST omitted */ );")
    assert "SH-001" in {hit.rule_id for hit in positive}
    negative = ruleset.match("<?php evaluation($value);")
    assert "SH-001" not in {hit.rule_id for hit in negative}
def test_literal_is_case_insensitive(ruleset):
    hits = ruleset.match("// family C99SHELL marker")
    literal_hits = [hit for hit in hits if hit.rule_id == "SH-031"]
    assert literal_hits and literal_hits[0].line == 1
    assert not [hit for hit in ruleset.match("// ordinary text") if hit.rule_id == "SH-031"]
def test_multiline_regex_crosses_lines(ruleset):
    source = "<?php\n$blob = base64_decode(\n  $payload\n);\neval ( /* payload omitted */ );\n"
    ids = {hit.rule_id for hit in ruleset.match(source)}
    assert {"SH-009", "SH-001"} <= ids
def test_token_sequence_approximate_and_negative(ruleset):
    positive = "<?php call_user_func ( /* gap */ $x = 1; $_POST['cb'] );"
    hits = ruleset.match(positive)
    assert "SH-030" in {hit.rule_id for hit in hits}
    negative = "<?php call_user_func ( $server_side_callback );"
    assert "SH-030" not in {hit.rule_id for hit in ruleset.match(negative)}
def test_custom_rule_load_and_override(tmp_path: Path):
    custom = tmp_path / "custom-rules"
    custom.mkdir()
    (custom / "override.yaml").write_text(
        rule_yaml("SH-001", "custom_needle").replace("weight: 21", "weight: 5"),
        encoding="utf-8",
    )
    loaded = load_ruleset(RULES_DIR, custom)
    assert loaded.by_id["SH-001"].name == "Custom marker"
    assert loaded.by_id["SH-001"].weight == 5
    assert len(loaded) >= 25
def test_custom_rule_added(tmp_path: Path):
    path = tmp_path / "one.yaml"
    path.write_text(rule_yaml("CUSTOM-900"), encoding="utf-8")
    rules = load_rule_file(path)
    assert rules[0].id == "CUSTOM-900"
    assert rules[0].weight == 21
def test_duplicate_rule_id_is_rejected(tmp_path: Path):
    path = tmp_path / "dupe.yaml"
    path.write_text(
        "rules:\n" + rule_yaml("DUP-001").split("rules:\n", 1)[1]
        + "  - id: DUP-001\n    name: Again\n    severity: low\n    weight: 1\n"
        + "    match: literal\n    pattern: x\n    description: d\n    remediation: r\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleError, match="duplicate rule id"):
        load_rule_file(path)
def test_bad_yaml_reports_line(tmp_path: Path):
    path = tmp_path / "bad.yaml"
    path.write_text("rules:\n  - id: [unterminated\n", encoding="utf-8")
    with pytest.raises(RuleError, match=r"bad\.yaml:\d+:"):
        load_rule_file(path)
def test_bad_regex_reports_line(tmp_path: Path):
    path = tmp_path / "bad-regex.yaml"
    path.write_text(rule_yaml("BAD-001", "("), encoding="utf-8")
    with pytest.raises(RuleError, match=r"bad-regex\.yaml:\d+:.*invalid regex"):
        load_rule_file(path)
def test_missing_field_is_rejected(tmp_path: Path):
    path = tmp_path / "missing.yaml"
    path.write_text(
        "rules:\n  - id: MISS-001\n    name: Incomplete\n    severity: low\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleError, match="missing required field"):
        load_rule_file(path)
def test_empty_rule_directory_is_rejected(tmp_path: Path):
    with pytest.raises(RuleError, match="no YAML rule files"):
        load_ruleset(tmp_path)
def test_compact_snippet_truncates_whitespace():
    text = "a\n\t b   " + "x" * 200
    snippet = compact_snippet(text)
    assert len(snippet) == 120
    assert "\n" not in snippet
    assert snippet.startswith("a b")
    assert snippet.endswith("...")
