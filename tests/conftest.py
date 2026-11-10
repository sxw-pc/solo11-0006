from __future__ import annotations
import sys
import time
from pathlib import Path
import pytest
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
from shellhunt.config import Config  # noqa: E402
from shellhunt.engine.rules import load_ruleset  # noqa: E402
from shellhunt.web.routes import create_app  # noqa: E402
RULES_DIR = PROJECT_ROOT / "shellhunt" / "ruleset"
KNOWN_BAD = RULES_DIR / "known_bad.sha256"
MALICIOUS_DIR = PROJECT_ROOT / "fixtures" / "corpus" / "malicious"
BENIGN_DIR = PROJECT_ROOT / "fixtures" / "corpus" / "benign"
SITE_DIR = PROJECT_ROOT / "fixtures" / "site_demo"
@pytest.fixture
def config(tmp_path: Path) -> Config:
    allowed = tmp_path / "allowed"
    demo = allowed / "demo"
    demo.mkdir(parents=True)
    return Config(
        data={
            "database": {"path": str(tmp_path / "data" / "test.db")},
            "scan": {"max_file_size": 1024 * 1024},
            "security": {
                "allowed_roots": [str(allowed)],
                "demo_target": str(demo),
            },
            "engine": {
                "rules_dir": str(RULES_DIR),
                "known_bad": str(KNOWN_BAD),
                "baseline": str(tmp_path / "data" / "baseline.json"),
                "custom_rules_dirs": [],
            },
        },
        base_dir=PROJECT_ROOT,
    )
@pytest.fixture
def ruleset():
    return load_ruleset(RULES_DIR)
@pytest.fixture
def allowed_root(config: Config) -> Path:
    return config.allowed_roots[0]
@pytest.fixture
def client(config: Config):
    app = create_app(config=config)
    app.config.update(TESTING=True)
    yield app.test_client()
@pytest.fixture
def wait_for_job():
    def _wait(client, job_id: int, timeout: float = 10.0) -> dict:
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            response = client.get(f"/api/scans/{job_id}")
            assert response.status_code == 200
            last = response.get_json()
            if last["status"] in ("done", "failed"):
                return last
            time.sleep(0.02)
        raise AssertionError(f"job {job_id} did not finish: {last}")
    return _wait
@pytest.fixture
def write_file(tmp_path: Path):
    def _write(relative: str, content: str | bytes, root: Path | None = None) -> Path:
        base = root or (tmp_path / "allowed")
        base.mkdir(parents=True, exist_ok=True)
        path = base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path
    return _write
