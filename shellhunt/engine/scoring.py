"""Explainable, capped weighted scoring."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from ..config import DEFAULT_CONFIG, deep_merge
from .entropy import EntropyReport
from .features import FeatureReport
from .rules import RuleHit
@dataclass
class ScoreResult:
    score: int
    verdict: str
    signals: list[dict[str, Any]]
    totals: dict[str, int]
    hash_override: bool = False
    known_bad_label: str | None = None
    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "signals": self.signals,
            "totals": self.totals,
            "hash_override": self.hash_override,
            "known_bad_label": self.known_bad_label,
        }
def _feature_map(features: FeatureReport | dict[str, Any]) -> dict[str, dict[str, Any]]:
    if hasattr(features, "signals"):
        return {name: sig.as_dict() for name, sig in features.signals.items()}
    return (features or {}).get("signals", {})
def _entropy_map(entropy: EntropyReport | dict[str, Any] | None) -> dict[str, Any]:
    if entropy is None:
        return {}
    if hasattr(entropy, "as_dict"):
        return entropy.as_dict()
    return entropy
def _verdict(score: int, thresholds: dict[str, int]) -> str:
    if score >= thresholds["malicious"]:
        return "malicious"
    if score >= thresholds["suspicious"]:
        return "suspicious"
    return "clean"
def score_file(
    matches: list[RuleHit],
    features: FeatureReport | dict[str, Any],
    entropy: EntropyReport | dict[str, Any] | None = None,
    known_bad_label: str | None = None,
    allowlisted_label: str | None = None,
    baseline_status: str | None = None,
    thresholds: dict[str, int] | None = None,
    scoring_config: dict[str, Any] | None = None,
) -> ScoreResult:
    config = deep_merge(DEFAULT_CONFIG["scoring"], scoring_config or {})
    thresholds = thresholds or DEFAULT_CONFIG["thresholds"]
    signals: list[dict[str, Any]] = []
    totals = {"rules": 0, "features": 0, "entropy": 0, "baseline": 0}
    if allowlisted_label and not known_bad_label:
        signals.append(
            {
                "kind": "allowlist",
                "label": "benign hash allowlist match",
                "points": 0,
                "detail": allowlisted_label,
                "override": True,
            }
        )
        return ScoreResult(0, "clean", signals, totals, False, None)
    hash_override = bool(known_bad_label)
    if known_bad_label:
        signals.append(
            {
                "kind": "hash",
                "label": "known-bad hash match",
                "points": 100,
                "detail": known_bad_label,
                "override": True,
            }
        )
    unique_rules: dict[str, RuleHit] = {}
    for hit in matches:
        unique_rules.setdefault(hit.rule_id, hit)
    remaining = int(config["rule_total_cap"])
    for hit in unique_rules.values():
        allowed = min(int(config["per_rule_cap"]), remaining, hit.weight)
        hit.points = max(0, allowed)
        remaining -= hit.points
        totals["rules"] += hit.points
        signals.append(
            {
                "kind": "rule",
                "label": hit.rule_name,
                "rule_id": hit.rule_id,
                "severity": hit.severity,
                "line": hit.line,
                "points": hit.points,
                "capped": allowed < hit.weight,
                "detail": f"{hit.rule_id} matched at line {hit.line}",
            }
        )
    remaining = int(config["feature_total_cap"])
    weights = config["feature_weights"]
    for name, signal in _feature_map(features).items():
        subscore = float(signal.get("score", 0))
        if subscore <= 0:
            continue
        raw = round(subscore * float(weights.get(name, 0)))
        points = max(0, min(raw, remaining))
        remaining -= points
        totals["features"] += points
        signals.append(
            {
                "kind": "feature",
                "label": name,
                "points": points,
                "capped": points < raw,
                "lines": signal.get("lines", []),
                "detail": signal.get("detail", ""),
            }
        )
    entropy = _entropy_map(entropy)
    remaining = int(config["entropy_total_cap"])
    entropy_candidates: list[tuple[str, int, str, bool]] = []
    if entropy.get("suspicious_count", 0):
        raw = int(entropy["suspicious_count"]) * int(
            config["entropy_weights"]["suspicious_string"]
        )
        limit = int(config["entropy_weights"]["suspicious_cap"])
        entropy_candidates.append(
            (
                "high-entropy payload strings",
                min(raw, limit),
                f"{entropy['suspicious_count']} suspicious string(s)",
                raw > limit,
            )
        )
    if entropy.get("encoding_depth", 0) >= 2:
        raw = int(entropy["encoding_depth"]) * int(
            config["entropy_weights"]["encoding_depth"]
        )
        limit = int(config["entropy_weights"]["encoding_cap"])
        entropy_candidates.append(
            (
                "nested encoding chain",
                min(raw, limit),
                "depth "
                + str(entropy["encoding_depth"])
                + ": "
                + ", ".join(entropy.get("encoding_functions", [])),
                raw > limit,
            )
        )
    high_entropy = entropy.get("overall", 0) >= 5.8 or (
        entropy.get("longest_entropy", 0) >= 5.5 and entropy.get("longest_length", 0) >= 80
    )
    if high_entropy:
        entropy_candidates.append(
            (
                "high overall entropy",
                int(config["entropy_weights"]["high_entropy"]),
                f"overall={entropy.get('overall')}",
                False,
            )
        )
    for label, raw, detail, capped_by_kind in entropy_candidates:
        points = max(0, min(raw, remaining))
        remaining -= points
        totals["entropy"] += points
        signals.append(
            {
                "kind": "entropy",
                "label": label,
                "points": points,
                "detail": detail,
                "capped": capped_by_kind or points < raw,
            }
        )
    if baseline_status in ("new", "modified"):
        weight = int(config["baseline_weights"].get(baseline_status + "_file", 0))
        weight = min(weight, int(config["baseline_total_cap"]))
        totals["baseline"] = weight
        signals.append(
            {
                "kind": "baseline",
                "label": f"baseline {baseline_status} file",
                "points": weight,
                "detail": "file is outside or changed from the clean baseline",
            }
        )
    computed = min(100, sum(totals.values()))
    score = 100 if hash_override else computed
    verdict = "malicious" if hash_override else _verdict(score, thresholds)
    return ScoreResult(score, verdict, signals, totals, hash_override, known_bad_label)
