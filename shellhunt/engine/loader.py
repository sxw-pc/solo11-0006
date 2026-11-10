"""Safe directory traversal, extension filtering, decoding and hashing."""
from __future__ import annotations
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from ..config import Config
from .hashdb import sha256_bytes
@dataclass
class SourceFile:
    absolute: Path
    relative: str
    size: int
@dataclass
class LoadedFile:
    absolute: Path
    relative: str
    size: int
    sha256: str
    encoding: str
    text: str
@dataclass
class SkippedFile:
    relative: str
    reason: str
    def as_dict(self) -> dict[str, str]:
        return {"path": self.relative, "reason": self.reason}
def _within(path: Path, root: Path) -> bool:
    try:
        candidate = os.path.normcase(str(path.resolve()))
        boundary = os.path.normcase(str(root.resolve()))
        return os.path.commonpath([candidate, boundary]) == boundary
    except ValueError:
        return False
def collect_files(
    root: str | Path, config: Config
) -> tuple[list[SourceFile], list[SkippedFile]]:
    """Walk a target without following symlinks and filter by extension/size."""
    root = Path(root).resolve()
    files: list[SourceFile] = []
    skipped: list[SkippedFile] = []
    for current, dirs, names in os.walk(root, followlinks=False):
        current_path = Path(current)
        kept_dirs = []
        for directory in sorted(dirs):
            candidate = current_path / directory
            if candidate.is_symlink() or not _within(candidate, root):
                relative = candidate.relative_to(root).as_posix()
                skipped.append(SkippedFile(relative, "symlink or path escape"))
            else:
                kept_dirs.append(directory)
        dirs[:] = kept_dirs
        for name in sorted(names):
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                skipped.append(SkippedFile(relative, "symlink"))
                continue
            if path.suffix.lower() not in config.extensions:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                skipped.append(SkippedFile(relative, "unreadable"))
                continue
            if size > config.max_file_size:
                skipped.append(SkippedFile(relative, "too large"))
                continue
            files.append(SourceFile(path, relative, size))
    files.sort(key=lambda item: item.relative)
    return files, skipped
def decode_bytes(data: bytes) -> tuple[str, str]:
    if data.startswith(b"\xef\xbb\xbf"):
        try:
            return data.decode("utf-8-sig"), "utf-8"
        except UnicodeDecodeError:
            pass
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("latin-1"), "latin-1"
def read_source(source: SourceFile, config: Config) -> tuple[LoadedFile | None, SkippedFile | None]:
    try:
        data = source.absolute.read_bytes()
    except OSError:
        return None, SkippedFile(source.relative, "unreadable")
    if len(data) > config.max_file_size:
        return None, SkippedFile(source.relative, "too large")
    if config.skip_binary and b"\x00" in data[:8192]:
        return None, SkippedFile(source.relative, "binary (NUL byte)")
    text, encoding = decode_bytes(data)
    return (
        LoadedFile(
            absolute=source.absolute,
            relative=source.relative,
            size=len(data),
            sha256=sha256_bytes(data),
            encoding=encoding,
            text=text,
        ),
        None,
    )
def load_sources(
    root: str | Path, config: Config
) -> tuple[list[LoadedFile], list[SkippedFile]]:
    sources, skipped = collect_files(root, config)
    loaded: list[LoadedFile] = []
    for source in sources:
        item, reason = read_source(source, config)
        if item is not None:
            loaded.append(item)
        elif reason is not None:
            skipped.append(reason)
    return loaded, skipped
def load_hashes(loaded: list[LoadedFile]) -> dict[str, str]:
    return {item.relative: item.sha256 for item in loaded}
def skip_summary(skipped: list[SkippedFile]) -> list[dict[str, Any]]:
    return [item.as_dict() for item in skipped]
