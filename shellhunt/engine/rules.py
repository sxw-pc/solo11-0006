"""YAML rule DSL: loading, validation and matching."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import yaml
from .tokenizer import Token, canonical, text_span, tokenize
SEVERITIES = {"low", "medium", "high", "critical"}
MATCH_TYPES = {"regex", "literal", "token_seq", "multiline_regex"}
REQUIRED_FIELDS = (
    "id",
    "name",
    "severity",
    "weight",
    "match",
    "pattern",
    "description",
    "remediation",
)
MAX_HITS_PER_RULE = 5
FLAG_MAP = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL, "x": re.VERBOSE}
class RuleError(ValueError):
    """A rule file is malformed; the message always carries a line number."""
@dataclass
class Rule:
    id: str
    name: str
    severity: str
    weight: int
    match: str
    pattern: Any
    description: str
    remediation: str
    flags: str = ""
    max_gap: int = 8
    source: str = ""
    line: int = 0
    _compiled: re.Pattern | None = field(default=None, repr=False)
    def compile(self) -> None:
        flag_value = 0
        for char in self.flags:
            flag_value |= FLAG_MAP.get(char, 0)
        if self.match in ("regex", "multiline_regex"):
            if self.match == "multiline_regex":
                flag_value |= re.MULTILINE | re.DOTALL
            try:
                self._compiled = re.compile(self.pattern, flag_value)
            except re.error as exc:
                raise RuleError(self._error(f"invalid regex: {exc}")) from exc
        elif self.match == "literal":
            self._compiled = re.compile(re.escape(self.pattern), re.IGNORECASE)
    def _error(self, message: str) -> str:
        return f"{self.source}:{self.line}: rule {self.id!r}: {message}"
@dataclass
class RuleHit:
    rule_id: str
    rule_name: str
    severity: str
    weight: int
    line: int
    snippet: str
    match_type: str
    points: int = 0
    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "weight": self.weight,
            "line": self.line,
            "snippet": self.snippet,
            "match_type": self.match_type,
            "points": self.points,
        }
def compact_snippet(raw: str, limit: int = 120) -> str:
    collapsed = re.sub(r"\s+", " ", raw).strip()
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 3] + "..."
def _line_at(text: str, index: int) -> int:
    return text.count("\n", 0, max(0, index)) + 1
class RuleSet:
    def __init__(self, rules: list[Rule]):
        self.rules = rules
        self.by_id = {rule.id: rule for rule in rules}
    def __len__(self) -> int:
        return len(self.rules)
    def match(self, text: str, tokens: list[Token] | None = None) -> list[RuleHit]:
        tokens = tokens if tokens is not None else tokenize(text)
        hits: list[RuleHit] = []
        for rule in self.rules:
            if rule.match == "token_seq":
                hits.extend(self._token_hits(rule, text, tokens))
            else:
                hits.extend(self._regex_hits(rule, text))
        return hits
    def _regex_hits(self, rule: Rule, text: str) -> list[RuleHit]:
        assert rule._compiled is not None
        results = []
        for match in rule._compiled.finditer(text):
            line = _line_at(text, match.start())
            results.append(
                RuleHit(
                    rule.id,
                    rule.name,
                    rule.severity,
                    rule.weight,
                    line,
                    compact_snippet(match.group(0)),
                    rule.match,
                )
            )
            if len(results) >= MAX_HITS_PER_RULE:
                break
        return results
    def _token_hits(self, rule: Rule, text: str, tokens: list[Token]) -> list[RuleHit]:
        wanted = _pattern_tokens(rule)
        results = []
        for start in range(len(tokens)):
            if canonical(tokens[start]) != wanted[0]:
                continue
            cursor, last = start + 1, start
            for target in wanted[1:]:
                found = -1
                for idx in range(cursor, min(len(tokens), cursor + rule.max_gap + 1)):
                    if canonical(tokens[idx]) == target:
                        found = idx
                        break
                if found < 0:
                    break
                cursor, last = found + 1, found
            else:
                results.append(
                    RuleHit(
                        rule.id,
                        rule.name,
                        rule.severity,
                        rule.weight,
                        tokens[start].line,
                        compact_snippet(text_span(tokens, start, last, text)),
                        rule.match,
                    )
                )
                if len(results) >= MAX_HITS_PER_RULE:
                    break
        return results
def _pattern_tokens(rule: Rule) -> list[str]:
    raw = rule.pattern
    if isinstance(raw, str):
        items = raw.split()
    else:
        items = list(raw)
    return [str(item).lower() if not str(item)[0].isdigit() else str(item) for item in items]
def _rule_from_item(
    item: Any, field_lines: dict[str, int], source: Path, item_line: int
) -> Rule:
    if not isinstance(item, dict):
        raise RuleError(f"{source}:{item_line}: each rule must be a mapping")
    for name in REQUIRED_FIELDS:
        if name not in item:
            raise RuleError(f"{source}:{item_line}: rule is missing required field {name!r}")
    line = field_lines.get("id", item_line)
    rule_id = str(item["id"]).strip()
    if not re.match(r"^[A-Za-z0-9_.-]{3,64}$", rule_id):
        raise RuleError(f"{source}:{line}: invalid rule id {rule_id!r}")
    severity = str(item["severity"]).lower()
    match = str(item["match"]).lower()
    if severity not in SEVERITIES:
        raise RuleError(f"{source}:{field_lines.get('severity', line)}: invalid severity")
    if match not in MATCH_TYPES:
        raise RuleError(f"{source}:{field_lines.get('match', line)}: invalid match type")
    try:
        weight = int(item["weight"])
    except (TypeError, ValueError) as exc:
        raise RuleError(f"{source}:{field_lines.get('weight', line)}: weight must be int") from exc
    if not 1 <= weight <= 100:
        raise RuleError(f"{source}:{field_lines.get('weight', line)}: weight must be 1..100")
    pattern = item["pattern"]
    if match == "token_seq":
        if isinstance(pattern, str):
            pattern = pattern.split()
        if not isinstance(pattern, list) or not pattern or not all(
            isinstance(part, (str, int)) and str(part).strip() for part in pattern
        ):
            raise RuleError(f"{source}:{field_lines.get('pattern', line)}: token_seq needs tokens")
        pattern = [str(part) for part in pattern]
    elif not isinstance(pattern, str) or not pattern.strip():
        raise RuleError(f"{source}:{field_lines.get('pattern', line)}: pattern is empty")
    flags = str(item.get("flags", "") or "")
    if any(char not in FLAG_MAP for char in flags):
        raise RuleError(f"{source}:{field_lines.get('flags', line)}: unsupported regex flags")
    try:
        max_gap = int(item.get("max_gap", 8))
    except (TypeError, ValueError) as exc:
        raise RuleError(f"{source}:{line}: max_gap must be an integer") from exc
    rule = Rule(
        id=rule_id,
        name=str(item["name"]),
        severity=severity,
        weight=weight,
        match=match,
        pattern=pattern,
        description=str(item["description"]),
        remediation=str(item["remediation"]),
        flags=flags,
        max_gap=max(0, min(max_gap, 50)),
        source=str(source),
        line=line,
    )
    rule.compile()
    return rule
def load_rule_file(path: str | Path) -> list[Rule]:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuleError(f"{path}: cannot read rules: {exc}") from exc
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
        data = yaml.safe_load(text)
    except yaml.MarkedYAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = mark.line + 1 if mark else 1
        raise RuleError(f"{path}:{line}: invalid YAML: {exc.problem or exc}") from exc
    except yaml.YAMLError as exc:
        raise RuleError(f"{path}:1: invalid YAML: {exc}") from exc
    items: Any
    item_nodes: list[Any]
    if isinstance(data, dict):
        items = data.get("rules")
        rule_node = None
        if isinstance(root, yaml.MappingNode):
            for key_node, value_node in root.value:
                if key_node.value == "rules":
                    rule_node = value_node
        item_nodes = list(rule_node.value) if isinstance(rule_node, yaml.SequenceNode) else []
    elif isinstance(data, list):
        items = data
        item_nodes = list(root.value) if isinstance(root, yaml.SequenceNode) else []
    else:
        raise RuleError(f"{path}:1: rules file must contain a 'rules' list")
    if not isinstance(items, list) or not items:
        raise RuleError(f"{path}:1: rules list is empty or missing")
    rules, seen = [], {}
    for index, item in enumerate(items):
        node = item_nodes[index] if index < len(item_nodes) else None
        item_line = node.start_mark.line + 1 if node is not None else 1
        field_lines = {}
        if isinstance(node, yaml.MappingNode):
            for key_node, _ in node.value:
                field_lines[key_node.value] = key_node.start_mark.line + 1
        rule = _rule_from_item(item, field_lines, path, item_line)
        if rule.id in seen:
            raise RuleError(
                f"{path}:{rule.line}: duplicate rule id {rule.id!r} "
                f"(first defined at line {seen[rule.id]})"
            )
        seen[rule.id] = rule.line
        rules.append(rule)
    return rules
def _load_directory(directory: str | Path) -> list[Rule]:
    directory = Path(directory)
    if not directory.is_dir():
        raise RuleError(f"{directory}: ruleset directory does not exist")
    files = sorted(list(directory.glob("*.yaml")) + list(directory.glob("*.yml")))
    if not files:
        raise RuleError(f"{directory}: no YAML rule files found")
    rules: list[Rule] = []
    for path in files:
        rules.extend(load_rule_file(path))
    ids = {rule.id for rule in rules}
    if len(ids) != len(rules):
        raise RuleError(f"{directory}: duplicate rule id across YAML files")
    return rules
def load_ruleset(
    rules_dir: str | Path, custom_dir: str | Path | None = None
) -> RuleSet:
    """Load built-in rules, merging a custom directory with same-id override."""
    builtin = _load_directory(rules_dir)
    if not custom_dir:
        return RuleSet(builtin)
    custom = _load_directory(custom_dir)
    merged = {rule.id: rule for rule in builtin}
    order = [rule.id for rule in builtin]
    for rule in custom:
        if rule.id not in merged:
            order.append(rule.id)
        merged[rule.id] = rule
    return RuleSet([merged[rule_id] for rule_id in order])
