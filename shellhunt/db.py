"""SQLite schema and small data-access layer."""
from __future__ import annotations
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    ruleset TEXT NOT NULL DEFAULT 'builtin',
    thresholds_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','running','done','failed')),
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    error TEXT,
    summary_json TEXT
);
CREATE TABLE IF NOT EXISTS file_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    encoding TEXT NOT NULL,
    size INTEGER NOT NULL,
    score INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    signals_json TEXT NOT NULL,
    features_json TEXT NOT NULL DEFAULT '{}',
    entropy_json TEXT NOT NULL DEFAULT '{}',
    known_bad_label TEXT,
    baseline_status TEXT,
    UNIQUE(job_id, path)
);
CREATE TABLE IF NOT EXISTS rule_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    file_id INTEGER NOT NULL REFERENCES file_results(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    weight INTEGER NOT NULL,
    line INTEGER NOT NULL,
    snippet TEXT NOT NULL,
    points INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_files_job ON file_results(job_id);
CREATE INDEX IF NOT EXISTS idx_hits_job ON rule_hits(job_id);
CREATE INDEX IF NOT EXISTS idx_hits_file ON rule_hits(file_id);
"""
def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
def _json_load(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default
class Database:
    """Each operation opens a short-lived connection, making it thread safe."""
    def __init__(self, path: str | Path):
        self.path = Path(path)
    def connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn
    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    def init(self) -> None:
        with self.connection() as conn:
            conn.executescript(SCHEMA)
    def create_job(
        self, target: str, ruleset: str, thresholds: dict[str, int] | None = None
    ) -> int:
        thresholds = thresholds or {"suspicious": 20, "malicious": 60}
        with self.connection() as conn:
            cur = conn.execute(
                "INSERT INTO jobs(target, ruleset, thresholds_json, status, created_at) "
                "VALUES (?, ?, ?, 'pending', ?)",
                (target, ruleset, json.dumps(thresholds), utc_now()),
            )
            return int(cur.lastrowid)
    def mark_running(self, job_id: int) -> None:
        with self.connection() as conn:
            conn.execute(
                "UPDATE jobs SET status='running', started_at=? WHERE id=? AND status='pending'",
                (utc_now(), job_id),
            )
    def finish_job(self, job_id: int, summary: dict[str, Any]) -> None:
        with self.connection() as conn:
            conn.execute(
                "UPDATE jobs SET status='done', finished_at=?, summary_json=?, error=NULL "
                "WHERE id=?",
                (utc_now(), json.dumps(summary, ensure_ascii=False), job_id),
            )
    def fail_job(self, job_id: int, error: str) -> None:
        with self.connection() as conn:
            conn.execute(
                "UPDATE jobs SET status='failed', finished_at=?, error=? WHERE id=?",
                (utc_now(), error[:2000], job_id),
            )
    def get_job(self, job_id: int) -> dict[str, Any] | None:
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return self._job(row)
    def list_jobs(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (int(limit),)
            ).fetchall()
        return [self._job(row) for row in rows]
    def delete_job(self, job_id: int) -> bool:
        with self.connection() as conn:
            cur = conn.execute("DELETE FROM jobs WHERE id=?", (job_id,))
            return cur.rowcount > 0
    def add_file_result(
        self,
        job_id: int,
        result: dict[str, Any],
        conn: sqlite3.Connection | None = None,
    ) -> int:
        own = conn is None
        conn = conn or self.connect()
        try:
            cur = conn.execute(
                "INSERT INTO file_results(job_id,path,sha256,encoding,size,score,verdict,"
                "signals_json,features_json,entropy_json,known_bad_label,baseline_status) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    job_id,
                    result["path"],
                    result["sha256"],
                    result["encoding"],
                    int(result["size"]),
                    int(result["score"]),
                    result["verdict"],
                    json.dumps(result.get("signals", []), ensure_ascii=False),
                    json.dumps(result.get("features", {}), ensure_ascii=False),
                    json.dumps(result.get("entropy", {}), ensure_ascii=False),
                    result.get("known_bad_label"),
                    result.get("baseline_status"),
                ),
            )
            file_id = int(cur.lastrowid)
            for hit in result.get("hits", []):
                conn.execute(
                    "INSERT INTO rule_hits(job_id,file_id,rule_id,rule_name,severity,"
                    "weight,line,snippet,points) VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        job_id,
                        file_id,
                        hit["rule_id"],
                        hit["rule_name"],
                        hit["severity"],
                        int(hit["weight"]),
                        int(hit["line"]),
                        hit["snippet"],
                        int(hit.get("points", 0)),
                    ),
                )
            if own:
                conn.commit()
            return file_id
        except Exception:
            if own:
                conn.rollback()
            raise
        finally:
            if own:
                conn.close()
    def get_file_results(self, job_id: int) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM file_results WHERE job_id=? ORDER BY score DESC, path ASC",
                (job_id,),
            ).fetchall()
        files = []
        for row in rows:
            item = dict(row)
            item["signals"] = _json_load(item.pop("signals_json", None), [])
            item["features"] = _json_load(item.pop("features_json", None), {})
            item["entropy"] = _json_load(item.pop("entropy_json", None), {})
            files.append(item)
        return files
    def get_hits(self, job_id: int) -> list[dict[str, Any]]:
        with self.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM rule_hits WHERE job_id=? ORDER BY file_id, line, id",
                (job_id,),
            ).fetchall()
        return [dict(row) for row in rows]
    def _job(self, row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        item = dict(row)
        item["thresholds"] = _json_load(item.pop("thresholds_json", None), {})
        item["summary"] = _json_load(item.pop("summary_json", None), None)
        return item
