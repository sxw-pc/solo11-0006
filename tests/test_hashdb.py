from __future__ import annotations
import json
from pathlib import Path
import pytest
from shellhunt.engine.hashdb import (
    HashDB,
    HashDBError,
    compare_baseline,
    generate_baseline,
    load_baseline,
    load_known_bad,
    sha256_bytes,
    sha256_file,
)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
KNOWN_BAD = PROJECT_ROOT / "shellhunt" / "ruleset" / "known_bad.sha256"
MALICIOUS = PROJECT_ROOT / "fixtures" / "corpus" / "malicious"
SITE_MODULES = PROJECT_ROOT / "fixtures" / "site_demo" / "modules"
def test_known_bad_loads_synthetic_corpus():
    database = load_known_bad(KNOWN_BAD)
    assert len(database) >= 35
    files = sorted(MALICIOUS.glob("*.phps")) + sorted(SITE_MODULES.glob("*.phps"))
    assert len(files) >= 40
    for path in files:
        assert database.lookup(sha256_file(path)), path.name
def test_hashdb_lookup_is_case_insensitive():
    digest = sha256_bytes(b"synthetic")
    database = HashDB({digest.upper(): "label"})
    assert database.lookup(digest) == "label"
    assert database.lookup("") is None
def test_invalid_hash_line_reports_number(tmp_path: Path):
    path = tmp_path / "bad.sha256"
    path.write_text("# header\nnot-a-hash label\n", encoding="utf-8")
    with pytest.raises(HashDBError, match=r"bad\.sha256:2:"):
        load_known_bad(path)
def test_duplicate_hash_is_rejected(tmp_path: Path):
    digest = "a" * 64
    path = tmp_path / "dupe.sha256"
    path.write_text(f"{digest} one\n{digest} two\n", encoding="utf-8")
    with pytest.raises(HashDBError, match="duplicate"):
        load_known_bad(path)
def test_missing_known_bad_file_is_an_error(tmp_path: Path):
    with pytest.raises(HashDBError, match="cannot read"):
        load_known_bad(tmp_path / "missing.sha256")
def test_baseline_new_modified_unchanged(tmp_path: Path):
    root = tmp_path / "clean"
    root.mkdir()
    (root / "a.phps").write_text("<?php echo 1;", encoding="utf-8")
    (root / "b.phps").write_text("<?php echo 2;", encoding="utf-8")
    (root / "notes.txt").write_text("ignored", encoding="utf-8")
    output = tmp_path / "baseline.json"
    count = generate_baseline(root, output, extensions={".phps"})
    assert count == 2
    baseline = load_baseline(output)
    assert baseline and baseline["files"]["a.phps"]
    (root / "b.phps").write_text("<?php echo 22;", encoding="utf-8")
    (root / "c.phps").write_text("<?php echo 3;", encoding="utf-8")
    current = {
        path.relative_to(root).as_posix(): sha256_file(path)
        for path in root.glob("*.phps")
    }
    result = compare_baseline(baseline, root, current)
    assert result["a.phps"] == "unchanged"
    assert result["b.phps"] == "modified"
    assert result["c.phps"] == "new"
def test_baseline_for_other_root_is_ignored(tmp_path: Path):
    baseline = {"root": str(tmp_path / "elsewhere"), "files": {}}
    result = compare_baseline(baseline, tmp_path / "target", {"a.phps": "x"})
    assert result == {}
def test_missing_baseline_returns_none(tmp_path: Path):
    assert load_baseline(tmp_path / "none.json") is None
def test_malformed_baseline_raises(tmp_path: Path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(["not", "a", "mapping"]), encoding="utf-8")
    with pytest.raises(HashDBError, match="invalid baseline"):
        load_baseline(path)
def test_sha256_helpers_agree(tmp_path: Path):
    payload = b"synthetic fixture bytes"
    path = tmp_path / "payload.bin"
    path.write_bytes(payload)
    assert sha256_bytes(payload) == sha256_file(path)
