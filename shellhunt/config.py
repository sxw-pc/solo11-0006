"""Configuration loading, validation and scan-target confinement."""
from __future__ import annotations
import copy
import os
from pathlib import Path
from typing import Any
import yaml
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG: dict[str, Any] = {
    "server": {"host": "127.0.0.1", "port": 8000},
    "database": {"path": "data/shellhunt.db"},
    "scan": {
        "extensions": [".php", ".phps", ".phtml", ".inc", ".asp", ".aspx", ".jsp", ".jspx"],
        "max_file_size": 2 * 1024 * 1024,
        "skip_binary": True,
    },
    "security": {
        "allowed_roots": ["fixtures"],
        "demo_target": "fixtures/site_demo",
    },
    "engine": {
        "rules_dir": "shellhunt/ruleset",
        "known_bad": "shellhunt/ruleset/known_bad.sha256",
        "allowlist": "shellhunt/ruleset/allowlist.sha256",
        "baseline": "data/baseline.json",
        "custom_rules_dirs": [],
    },
    "thresholds": {"suspicious": 20, "malicious": 60},
    "scoring": {
        "per_rule_cap": 40,
        "rule_total_cap": 70,
        "feature_total_cap": 40,
        "entropy_total_cap": 15,
        "baseline_total_cap": 15,
        "feature_weights": {
            "direct_input": 22,
            "dynamic_call": 18,
            "dangerous_calls": 8,
            "obfuscation": 10,
        },
        "entropy_weights": {
            "suspicious_string": 2,
            "suspicious_cap": 8,
            "encoding_depth": 4,
            "encoding_cap": 12,
            "high_entropy": 3,
        },
        "baseline_weights": {"new_file": 8, "modified_file": 12},
    },
}
class ConfigError(ValueError):
    """Raised for malformed configuration or unknown rulesets."""
class TargetValidationError(ValueError):
    """Raised when a requested scan target is outside the allowed roots."""
def deep_merge(base: dict, override: dict) -> dict:
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result
def _read_yaml(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"config root must be a mapping: {path}")
    return data
def _env_overrides() -> dict:
    overrides: dict[str, Any] = {}
    if os.environ.get("SHELLHUNT_HOST"):
        overrides.setdefault("server", {})["host"] = os.environ["SHELLHUNT_HOST"]
    if os.environ.get("SHELLHUNT_PORT"):
        overrides.setdefault("server", {})["port"] = int(os.environ["SHELLHUNT_PORT"])
    if os.environ.get("SHELLHUNT_DB_PATH"):
        overrides.setdefault("database", {})["path"] = os.environ["SHELLHUNT_DB_PATH"]
    if os.environ.get("SHELLHUNT_ALLOWED_ROOTS"):
        roots = [p for p in os.environ["SHELLHUNT_ALLOWED_ROOTS"].split(os.pathsep) if p]
        overrides.setdefault("security", {})["allowed_roots"] = roots
    return overrides
class Config:
    """Typed view over the merged YAML/environment configuration."""
    def __init__(self, data: dict | None = None, base_dir: str | Path | None = None):
        self.base_dir = Path(base_dir or PROJECT_ROOT).resolve()
        raw = deep_merge(DEFAULT_CONFIG, data or {})
        server = raw["server"]
        self.host = str(server["host"])
        self.port = int(server["port"])
        self.db_path = self._path(raw["database"]["path"])
        scan = raw["scan"]
        self.extensions = {
            ("." + str(ext).lower().lstrip(".")) for ext in scan["extensions"] if str(ext).strip()
        }
        self.max_file_size = int(scan["max_file_size"])
        self.skip_binary = bool(scan["skip_binary"])
        self.allowed_roots = [self._path(p) for p in raw["security"]["allowed_roots"]]
        if not self.allowed_roots:
            raise ConfigError("security.allowed_roots must not be empty")
        self.demo_target = self._path(raw["security"]["demo_target"])
        engine = raw["engine"]
        self.rules_dir = self._path(engine["rules_dir"])
        self.known_bad_path = self._path(engine["known_bad"])
        self.allowlist_path = self._path(
            engine.get("allowlist", "shellhunt/ruleset/allowlist.sha256")
        )
        self.baseline_path = self._path(engine["baseline"])
        self.custom_rules_dirs = [self._path(p) for p in engine.get("custom_rules_dirs") or []]
        self.thresholds = {
            "suspicious": int(raw["thresholds"]["suspicious"]),
            "malicious": int(raw["thresholds"]["malicious"]),
        }
        if not 0 <= self.thresholds["suspicious"] < self.thresholds["malicious"] <= 100:
            raise ConfigError("thresholds must satisfy 0 <= suspicious < malicious <= 100")
        self.scoring = raw["scoring"]
        if self.max_file_size <= 0:
            raise ConfigError("scan.max_file_size must be positive")
        if not self.extensions:
            raise ConfigError("scan.extensions must not be empty")
    @property
    def project_root(self) -> Path:
        return PROJECT_ROOT
    def _path(self, value: str | Path) -> Path:
        path = Path(str(value)).expanduser()
        if not path.is_absolute():
            path = self.base_dir / path
        return path.resolve()
    def ruleset_names(self) -> list[str]:
        names = ["builtin"]
        for directory in self.custom_rules_dirs:
            if directory.name not in names:
                names.append(directory.name)
        return names
    def custom_ruleset_dir(self, name: str) -> Path | None:
        if name in (None, "", "builtin"):
            return None
        for directory in self.custom_rules_dirs:
            if directory.name == name:
                return directory
        raise ConfigError(f"unknown ruleset: {name}")
    def is_within_allowed(self, path: Path) -> bool:
        resolved = path.resolve()
        for root in self.allowed_roots:
            root = root.resolve()
            try:
                if os.path.commonpath([str(resolved), str(root)]) == str(root):
                    return True
            except ValueError:
                continue
        return False
    def validate_target(self, raw_target: str | Path | None) -> Path:
        """Resolve a scan target and reject traversal or symlink escapes."""
        if raw_target is None or not str(raw_target).strip():
            raise TargetValidationError("scan target is required")
        text = str(raw_target).strip()
        if "\x00" in text:
            raise TargetValidationError("invalid NUL byte in target")
        normalised = text.replace("\\", "/")
        if ".." in normalised.split("/"):
            raise TargetValidationError("path traversal is not allowed")
        candidate = Path(text).expanduser()
        if not candidate.is_absolute():
            candidate = self.base_dir / candidate
        resolved = candidate.resolve()
        if not resolved.exists():
            raise TargetValidationError("scan target does not exist")
        if not resolved.is_dir():
            raise TargetValidationError("scan target must be a directory")
        if not self.is_within_allowed(resolved):
            raise TargetValidationError("scan target is outside the allowed roots")
        return resolved
def load_config(path: str | Path | None = None) -> Config:
    """Load config.yaml (or config.example.yaml), then apply env overrides."""
    chosen: Path | None = None
    if path:
        chosen = Path(path).expanduser().resolve()
        if not chosen.exists():
            raise ConfigError(f"config file not found: {chosen}")
    else:
        env_path = os.environ.get("SHELLHUNT_CONFIG")
        if env_path:
            chosen = Path(env_path).expanduser().resolve()
        elif (PROJECT_ROOT / "config.yaml").exists():
            chosen = PROJECT_ROOT / "config.yaml"
        elif (PROJECT_ROOT / "config.example.yaml").exists():
            chosen = PROJECT_ROOT / "config.example.yaml"
    data: dict[str, Any] = {}
    base_dir = PROJECT_ROOT
    if chosen:
        data = _read_yaml(chosen)
        base_dir = chosen.parent
    data = deep_merge(data, _env_overrides())
    return Config(data=data, base_dir=base_dir)
