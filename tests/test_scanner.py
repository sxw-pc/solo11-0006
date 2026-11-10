from __future__ import annotations
from pathlib import Path
import pytest
from shellhunt.config import TargetValidationError, load_config
from shellhunt.db import Database
from shellhunt.engine.hashdb import generate_baseline
from shellhunt.engine.loader import collect_files, load_sources
from shellhunt.engine.rules import load_ruleset
from shellhunt.engine.scanner import scan_directory, scan_to_database
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = PROJECT_ROOT / "shellhunt" / "ruleset"
@pytest.fixture(scope="module")
def builtin_rules():
    return load_ruleset(RULES_DIR)
def test_corpus_regression_and_demo(builtin_rules):
    config = load_config()
    malicious = scan_directory(
        config, PROJECT_ROOT / "fixtures" / "corpus" / "malicious", builtin_rules
    )
    assert malicious["summary"]["total_files"] == 35
    assert all(item["verdict"] in ("suspicious", "malicious") for item in malicious["files"])
    assert all(
        item["verdict"] == "malicious"
        for item in malicious["files"]
        if item["known_bad_label"]
    )
    benign = scan_directory(config, PROJECT_ROOT / "fixtures" / "corpus" / "benign", builtin_rules)
    assert benign["summary"]["total_files"] == 26
    assert {item["verdict"] for item in benign["files"]} == {"clean"}
    demo = scan_directory(config, PROJECT_ROOT / "fixtures" / "site_demo", builtin_rules)
    backdoors = [item for item in demo["files"] if item["known_bad_label"]]
    assert 5 <= len(backdoors) <= 8
    assert all(item["verdict"] == "malicious" for item in backdoors)
    assert demo["summary"]["by_verdict"]["clean"] >= 20
def test_target_must_be_inside_allowed_root(config, tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(TargetValidationError):
        config.validate_target(outside)
    with pytest.raises(TargetValidationError):
        config.validate_target(str(config.allowed_roots[0] / ".." / "outside"))
def test_scanner_rejects_traversal_prefix(config):
    with pytest.raises(TargetValidationError, match="traversal"):
        config.validate_target("../fixtures")
def test_collect_skips_binary_large_and_foreign_extensions(config, write_file):
    config.max_file_size = 100
    write_file("normal.phps", "<?php echo 'ok';")
    write_file("binary.phps", b"<?php echo 1;\x00\x01")
    write_file("large.phps", "x" * 200)
    write_file("notes.txt", "ignored")
    sources, skipped = collect_files(config.allowed_roots[0], config)
    assert {item.relative for item in sources} == {"binary.phps", "normal.phps"}
    reasons = {item.relative: item.reason for item in skipped}
    assert reasons["large.phps"] == "too large"
    loaded, more_skipped = load_sources(config.allowed_roots[0], config)
    assert [item.relative for item in loaded] == ["normal.phps"]
    assert {item.relative: item.reason for item in more_skipped}["binary.phps"].startswith(
        "binary"
    )
def test_latin1_encoding_is_recorded(config, write_file, builtin_rules):
    write_file("legacy.phps", b"<?php\n$name = 'caf\xe9';\n")
    report = scan_directory(config, config.allowed_roots[0], builtin_rules)
    legacy = next(item for item in report["files"] if item["path"] == "legacy.phps")
    assert legacy["encoding"] == "latin-1"
def test_symlink_file_escape_is_skipped(config, tmp_path: Path, write_file):
    secret = tmp_path / "secret.phps"
    secret.write_text("<?php echo 'outside';", encoding="utf-8")
    link = config.allowed_roots[0] / "link.phps"
    try:
        link.symlink_to(secret)
    except OSError:
        pytest.skip("symlink creation is unavailable on this platform")
    sources, skipped = collect_files(config.allowed_roots[0], config)
    assert "link.phps" not in [item.relative for item in sources]
    assert any(item.relative == "link.phps" for item in skipped)
def test_symlink_target_escape_is_rejected(config, tmp_path: Path):
    outside = tmp_path / "outside-dir"
    outside.mkdir()
    link = config.allowed_roots[0] / "escape"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable on this platform")
    with pytest.raises(TargetValidationError):
        config.validate_target(link)
def test_scan_results_are_persisted(config, allowed_root: Path, builtin_rules):
    (allowed_root / "backdoor.phps").write_text(
        "<?php\neval ( /* $_POST['x'] omitted */ );\n", encoding="utf-8"
    )
    db = Database(config.db_path)
    db.init()
    job_id = db.create_job(str(allowed_root), "builtin", config.thresholds)
    db.mark_running(job_id)
    report = scan_to_database(
        config, db, job_id, allowed_root, builtin_rules, config.thresholds
    )
    job = db.get_job(job_id)
    assert job["status"] == "done"
    assert report["summary"]["by_verdict"]["malicious"] == 1
    files = db.get_file_results(job_id)
    assert files[0]["path"] == "backdoor.phps"
    assert files[0]["features"]["signals"]
    hits = db.get_hits(job_id)
    assert hits[0]["rule_id"] in {"SH-001", "SH-007"}
    assert hits[0]["points"] > 0
def test_baseline_marks_new_files(config, allowed_root: Path, builtin_rules, write_file):
    write_file("existing.phps", "<?php echo 'safe';", root=allowed_root)
    count = generate_baseline(allowed_root, config.baseline_path, config.extensions)
    assert count == 1
    (allowed_root / "new.phps").write_text("<?php echo 'new';", encoding="utf-8")
    report = scan_directory(config, allowed_root, builtin_rules)
    assert report["summary"]["baseline_applied"] is True
    by_path = {item["path"]: item for item in report["files"]}
    assert by_path["existing.phps"]["baseline_status"] == "unchanged"
    assert by_path["new.phps"]["baseline_status"] == "new"
def test_allowlisted_hash_is_clean(config, allowed_root: Path, builtin_rules, tmp_path: Path):
    sample = allowed_root / "reviewed.phps"
    sample.write_text("<?php\neval ( /* $_POST['x'] omitted */ );\n", encoding="utf-8")
    from shellhunt.engine.hashdb import sha256_file
    allow = tmp_path / "allowlist.sha256"
    allow.write_text(f"{sha256_file(sample)}  reviewed-by-security\n", encoding="utf-8")
    config.allowlist_path = allow
    report = scan_directory(config, allowed_root, builtin_rules)
    item = next(entry for entry in report["files"] if entry["path"] == "reviewed.phps")
    assert item["score"] == 0
    assert item["verdict"] == "clean"
    assert any(signal["kind"] == "allowlist" for signal in item["signals"])
def test_empty_directory_scans_cleanly(config, builtin_rules):
    report = scan_directory(config, config.allowed_roots[0], builtin_rules)
    assert report["summary"]["total_files"] == 0
    assert report["summary"]["by_verdict"]["clean"] == 0
