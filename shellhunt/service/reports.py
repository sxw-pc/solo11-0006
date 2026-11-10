"""Build machine-readable and self-contained HTML reports from the database."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from jinja2 import Environment, FileSystemLoader, select_autoescape
from ..db import Database
WEB_DIR = Path(__file__).resolve().parent.parent / "web"
def build_report(db: Database, job_id: int) -> dict[str, Any] | None:
    job = db.get_job(job_id)
    if job is None:
        return None
    files = db.get_file_results(job_id)
    hits = db.get_hits(job_id)
    by_file: dict[int, list[dict[str, Any]]] = {}
    for hit in hits:
        by_file.setdefault(hit["file_id"], []).append(hit)
    for item in files:
        item["hits"] = by_file.get(item["id"], [])
        if item.get("baseline_status") == "unchanged":
            item["baseline_status"] = "unchanged"
    summary = job.get("summary") or {}
    return {
        "schema": "shellhunt.report.v1",
        "job": {
            "id": job["id"],
            "target": job["target"],
            "ruleset": job["ruleset"],
            "status": job["status"],
            "created_at": job["created_at"],
            "started_at": job["started_at"],
            "finished_at": job["finished_at"],
            "error": job["error"],
            "thresholds": job["thresholds"],
        },
        "summary": summary,
        "files": files,
        "generated_at": summary.get("generated_at") or job["finished_at"],
    }
def report_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)
def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(WEB_DIR / "templates")),
        autoescape=select_autoescape(["html", "xml"]),
    )
def report_html(report: dict[str, Any]) -> str:
    css = (WEB_DIR / "static" / "style.css").read_text(encoding="utf-8")
    template = _environment().get_template("report.html")
    return template.render(report=report, inline_css=css)
