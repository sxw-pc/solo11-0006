"""Known-bad hash lookup and clean-baseline generation/comparison."""
from __future__ import annotations
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any
from ..db import utc_now
HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")
class HashDBError(ValueError):
    pass
class HashDB:
    def __init__(self, mapping: dict[str, str] | None = None):
        self.mapping = {key.lower(): value for key, value in (mapping or {}).items()}
    def lookup(self, digest: str) -> str | None:
        return self.mapping.get((digest or "").lower())
    def __len__(self) -> int:
        return len(self.mapping)
def load_known_bad(path: str | Path) -> HashDB:
    path = Path(path)
    mapping: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise HashDBError(f"cannot read known-bad hash file {path}: {exc}") from exc
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        digest = parts[0].lower()
        if not HASH_RE.match(digest):
            raise HashDBError(f"{path}:{number}: invalid sha256 value")
        if digest in mapping:
            raise HashDBError(f"{path}:{number}: duplicate sha256 value")
        mapping[digest] = parts[1].strip() if len(parts) > 1 else "known synthetic sample"
    return HashDB(mapping)
def load_allowlist(path: str | Path) -> HashDB:
    """Load the optional benign allowlist (missing file means no overrides)."""
    path = Path(path)
    if not path.exists():
        return HashDB()
    return load_known_bad(path)
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 64), b""):
            digest.update(chunk)
    return digest.hexdigest()
def generate_baseline(
    directory: str | Path,
    output_path: str | Path,
    extensions: set[str] | None = None,
    max_file_size: int = 2 * 1024 * 1024,
) -> int:
    root = Path(directory).resolve()
    if not root.is_dir():
        raise HashDBError(f"baseline source is not a directory: {root}")
    files: dict[str, str] = {}
    for current, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if not (Path(current) / d).is_symlink())
        for name in sorted(names):
            path = Path(current) / name
            if path.is_symlink():
                continue
            if extensions is not None and path.suffix.lower() not in extensions:
                continue
            try:
                if path.stat().st_size > max_file_size:
                    continue
                relative = path.relative_to(root).as_posix()
                files[relative] = sha256_file(path)
            except OSError:
                continue
    payload = {
        "version": 1,
        "root": str(root),
        "created_at": utc_now(),
        "files": dict(sorted(files.items())),
    }
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return len(files)
def load_baseline(path: str | Path) -> dict[str, Any] | None:
    path = Path(path)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HashDBError(f"cannot read baseline {path}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("files"), dict):
        raise HashDBError(f"invalid baseline format: {path}")
    return data
def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left.resolve())) == os.path.normcase(str(right.resolve()))
def compare_baseline(
    baseline: dict[str, Any] | None,
    target: str | Path,
    current_hashes: dict[str, str],
) -> dict[str, str]:
    """Return relpath -> 'new' | 'modified' | 'unchanged' (when baseline applies)."""
    if not baseline:
        return {}
    try:
        base_root = Path(str(baseline.get("root", "")))
    except (TypeError, ValueError):
        return {}
    if not _same_path(base_root, Path(target)):
        return {}
    known = baseline.get("files", {})
    result = {}
    for relative, digest in current_hashes.items():
        if relative not in known:
            result[relative] = "new"
        elif str(known[relative]).lower() != digest.lower():
            result[relative] = "modified"
        else:
            result[relative] = "unchanged"
    return result
