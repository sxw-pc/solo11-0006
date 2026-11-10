"""Scan orchestration: load -> match -> features -> score -> persist."""
from __future__ import annotations
from collections import Counter
from pathlib import Path
from typing import Any
from ..config import Config
from ..db import Database, utc_now
from .entropy import analyze_entropy
from .features import analyze_features
from .hashdb import compare_baseline, load_allowlist, load_baseline, load_known_bad
from .loader import load_hashes, load_sources, skip_summary
from .rules import RuleSet
from .scoring import score_file
from .tokenizer import tokenize
def _summary(
    files: list[dict[str, Any]],
    skipped: list[dict[str, str]],
    baseline_applied: bool,
) -> dict[str, Any]:
    counts = Counter(item["verdict"] for item in files)
    ranking: dict[str, dict[str, Any]] = {}
    total_hits = 0
    for item in files:
        for hit in item["hits"]:
            total_hits += 1
            entry = ranking.setdefault(
                hit["rule_id"],
                {
                    "rule_id": hit["rule_id"],
                    "rule_name": hit["rule_name"],
                    "severity": hit["severity"],
                    "count": 0,
                    "files": 0,
                    "_paths": set(),
                },
            )
            entry["count"] += 1
            entry["_paths"].add(item["path"])
    for entry in ranking.values():
        entry["files"] = len(entry.pop("_paths"))
    ordered_ranking = sorted(
        ranking.values(), key=lambda item: (-item["count"], item["rule_id"])
    )
    top_risk = [
        {"path": item["path"], "score": item["score"], "verdict": item["verdict"]}
        for item in sorted(files, key=lambda item: (-item["score"], item["path"]))[:10]
    ]
    return {
        "total_files": len(files),
        "by_verdict": {
            "clean": counts.get("clean", 0),
            "suspicious": counts.get("suspicious", 0),
            "malicious": counts.get("malicious", 0),
        },
        "total_hits": total_hits,
        "hash_matches": sum(1 for item in files if item.get("known_bad_label")),
        "baseline_applied": baseline_applied,
        "skipped": len(skipped),
        "skipped_files": skipped,
        "top_risk": top_risk,
        "rule_ranking": ordered_ranking,
        "generated_at": utc_now(),
    }
def scan_directory(
    config: Config,
    target: str | Path,
    ruleset: RuleSet,
    thresholds: dict[str, int] | None = None,
    baseline_path: str | Path | None = None,
) -> dict[str, Any]:
    """Scan a directory in memory.  The target must be inside allowed roots."""
    resolved = config.validate_target(target)
    thresholds = thresholds or dict(config.thresholds)
    known = load_known_bad(config.known_bad_path)
    allowlist = load_allowlist(config.allowlist_path)
    baseline = load_baseline(baseline_path or config.baseline_path)
    loaded, skipped = load_sources(resolved, config)
    skipped_dicts = skip_summary(skipped)
    hashes = load_hashes(loaded)
    baseline_map = compare_baseline(baseline, resolved, hashes)
    files: list[dict[str, Any]] = []
    for source in loaded:
        tokens = tokenize(source.text)
        hits = ruleset.match(source.text, tokens)
        features = analyze_features(source.text, tokens)
        entropy = analyze_entropy(source.text, tokens)
        baseline_status = baseline_map.get(source.relative)
        known_label = known.lookup(source.sha256)
        allow_label = allowlist.lookup(source.sha256)
        score = score_file(
            hits,
            features,
            entropy,
            known_bad_label=known_label,
            allowlisted_label=allow_label,
            baseline_status=baseline_status,
            thresholds=thresholds,
            scoring_config=config.scoring,
        )
        files.append(
            {
                "path": source.relative,
                "sha256": source.sha256,
                "encoding": source.encoding,
                "size": source.size,
                "score": score.score,
                "verdict": score.verdict,
                "signals": score.signals,
                "score_totals": score.totals,
                "hits": [hit.as_dict() for hit in hits],
                "features": features.as_dict(),
                "entropy": entropy.as_dict(),
                "known_bad_label": known_label,
                "baseline_status": baseline_status,
            }
        )
    summary = _summary(files, skipped_dicts, bool(baseline_map))
    return {
        "target": str(resolved),
        "thresholds": thresholds,
        "files": files,
        "skipped": skipped_dicts,
        "summary": summary,
        "generated_at": summary["generated_at"],
    }
def scan_to_database(
    config: Config,
    db: Database,
    job_id: int,
    target: str | Path,
    ruleset: RuleSet,
    thresholds: dict[str, int] | None = None,
) -> dict[str, Any]:
    report = scan_directory(config, target, ruleset, thresholds)
    with db.connection() as conn:
        for result in report["files"]:
            db.add_file_result(job_id, result, conn)
    db.finish_job(job_id, report["summary"])
    return report
