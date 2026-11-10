"""Background scan-job lifecycle: pending -> running -> done/failed."""
from __future__ import annotations
import threading
import time
from pathlib import Path
from typing import Any
from ..config import Config, ConfigError
from ..db import Database
from ..engine.rules import load_ruleset
from ..engine.scanner import scan_to_database
class JobManager:
    def __init__(self, config: Config, db: Database | None = None):
        self.config = config
        self.db = db or Database(config.db_path)
        self.db.init()
        self._threads: dict[int, threading.Thread] = {}
        self._lock = threading.Lock()
    def thresholds(self, overrides: dict[str, Any] | None = None) -> dict[str, int]:
        values = dict(self.config.thresholds)
        for key in ("suspicious", "malicious"):
            if overrides and overrides.get(key) is not None:
                try:
                    values[key] = int(overrides[key])
                except (TypeError, ValueError) as exc:
                    raise ConfigError(f"invalid {key} threshold") from exc
        if not 0 <= values["suspicious"] < values["malicious"] <= 100:
            raise ConfigError("thresholds must satisfy 0 <= suspicious < malicious <= 100")
        return values
    def submit(
        self,
        target: str | Path,
        ruleset_name: str = "builtin",
        thresholds: dict[str, Any] | None = None,
    ) -> int:
        resolved = self.config.validate_target(target)
        thresholds = self.thresholds(thresholds)
        custom_dir = self.config.custom_ruleset_dir(ruleset_name)
        ruleset = load_ruleset(self.config.rules_dir, custom_dir)
        job_id = self.db.create_job(str(resolved), ruleset_name or "builtin", thresholds)
        thread = threading.Thread(
            target=self._run,
            args=(job_id, resolved, ruleset, thresholds),
            name=f"shellhunt-scan-{job_id}",
            daemon=True,
        )
        with self._lock:
            self._threads[job_id] = thread
        thread.start()
        return job_id
    def _run(
        self,
        job_id: int,
        target: Path,
        ruleset: Any,
        thresholds: dict[str, int],
    ) -> None:
        self.db.mark_running(job_id)
        try:
            scan_to_database(
                self.config,
                self.db,
                job_id,
                target,
                ruleset,
                thresholds,
            )
        except Exception as exc:  # noqa: BLE001 - failure must reach the UI
            self.db.fail_job(job_id, f"{type(exc).__name__}: {exc}")
    def wait(self, job_id: int, timeout: float = 15.0) -> dict[str, Any] | None:
        """Test/CLI helper: wait for the worker without blocking the web UI."""
        deadline = time.monotonic() + timeout
        with self._lock:
            thread = self._threads.get(job_id)
        if thread:
            thread.join(max(0.0, deadline - time.monotonic()))
        while time.monotonic() < deadline:
            job = self.db.get_job(job_id)
            if job and job["status"] in ("done", "failed"):
                return job
            time.sleep(0.01)
        return self.db.get_job(job_id)
