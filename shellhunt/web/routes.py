"""Flask pages and JSON API."""
from __future__ import annotations
from typing import Any
from flask import Flask, Response, abort, jsonify, redirect, render_template, request, url_for
from ..config import Config, ConfigError, TargetValidationError, load_config
from ..db import Database
from ..engine.rules import RuleError
from ..service.jobs import JobManager
from ..service.reports import build_report, report_html, report_json
def create_app(config: Config | None = None, config_path: str | None = None) -> Flask:
    config = config or load_config(config_path)
    db = Database(config.db_path)
    db.init()
    jobs = JobManager(config, db)
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SHELLHUNT"] = config
    app.config["JSON_AS_ASCII"] = False
    app.extensions["shellhunt_config"] = config
    app.extensions["shellhunt_db"] = db
    app.extensions["shellhunt_jobs"] = jobs
    def target_options() -> list[dict[str, str]]:
        options: list[dict[str, str]] = []
        seen: set[str] = set()
        for root in config.allowed_roots:
            candidates = [root]
            if root.is_dir():
                candidates += sorted(
                    (child for child in root.iterdir() if child.is_dir() and not child.is_symlink()),
                    key=lambda item: str(item).lower(),
                )
            for candidate in candidates:
                key = str(candidate.resolve())
                if key in seen or not candidate.is_dir():
                    continue
                seen.add(key)
                try:
                    label = str(candidate.resolve().relative_to(config.base_dir))
                except ValueError:
                    label = key
                options.append({"path": key, "label": label})
        return options
    def payload() -> dict[str, Any]:
        if request.is_json:
            data = request.get_json(silent=True)
            return data if isinstance(data, dict) else {}
        return request.form.to_dict()
    def create_job(data: dict[str, Any]) -> int:
        nested = data.get("thresholds") if isinstance(data.get("thresholds"), dict) else {}
        thresholds = {
            "suspicious": nested.get("suspicious", data.get("suspicious")),
            "malicious": nested.get("malicious", data.get("malicious")),
        }
        return jobs.submit(
            data.get("target"),
            str(data.get("ruleset") or "builtin"),
            thresholds if any(v is not None and v != "" for v in thresholds.values()) else None,
        )
    @app.get("/")
    def index():
        return render_template(
            "index.html",
            jobs=db.list_jobs(50),
            targets=target_options(),
            rulesets=config.ruleset_names(),
            demo_exists=config.demo_target.is_dir(),
            thresholds=config.thresholds,
        )
    @app.post("/scans")
    def create_scan_page():
        try:
            job_id = create_job(payload())
        except (ConfigError, TargetValidationError, RuleError) as exc:
            return render_template("error.html", message=str(exc)), 400
        return redirect(url_for("job_detail", job_id=job_id), code=303)
    @app.post("/demo")
    def demo_scan():
        try:
            if not config.demo_target.is_dir():
                raise TargetValidationError("demo site is not available")
            job_id = jobs.submit(config.demo_target, "builtin", None)
        except (ConfigError, TargetValidationError, RuleError) as exc:
            return render_template("error.html", message=str(exc)), 400
        return redirect(url_for("job_detail", job_id=job_id), code=303)
    @app.get("/scans/<int:job_id>")
    def job_detail(job_id: int):
        job = db.get_job(job_id)
        if not job:
            abort(404)
        report = build_report(db, job_id)
        return render_template(
            "job_detail.html",
            job=job,
            files=report["files"] if report else [],
            summary=job.get("summary") or {},
        )
    @app.post("/scans/<int:job_id>/delete")
    def delete_job(job_id: int):
        if not db.get_job(job_id):
            abort(404)
        db.delete_job(job_id)
        return redirect(url_for("index"), code=303)
    @app.get("/api/scans")
    def api_list():
        return jsonify({"jobs": db.list_jobs(100)})
    @app.post("/api/scans")
    def api_create():
        try:
            job_id = create_job(payload())
        except (ConfigError, TargetValidationError, RuleError) as exc:
            return jsonify({"error": str(exc)}), 400
        job = db.get_job(job_id)
        return (
            jsonify(
                {
                    "job_id": job_id,
                    "status": job["status"] if job else "pending",
                    "status_url": url_for("api_job", job_id=job_id),
                }
            ),
            202,
        )
    @app.get("/api/scans/<int:job_id>")
    def api_job(job_id: int):
        job = db.get_job(job_id)
        if not job:
            return jsonify({"error": "job not found"}), 404
        return jsonify(job)
    @app.get("/api/scans/<int:job_id>/report")
    def api_report(job_id: int):
        job = db.get_job(job_id)
        if not job:
            return jsonify({"error": "job not found"}), 404
        if job["status"] != "done":
            return jsonify({"error": f"job is {job['status']}", "status": job["status"]}), 409
        report = build_report(db, job_id)
        return Response(report_json(report), mimetype="application/json")
    @app.get("/reports/<int:job_id>.json")
    def export_json(job_id: int):
        job = db.get_job(job_id)
        if not job:
            abort(404)
        if job["status"] != "done":
            return render_template("error.html", message="report is not ready"), 409
        report = build_report(db, job_id)
        return Response(
            report_json(report),
            mimetype="application/json",
            headers={
                "Content-Disposition": f"attachment; filename=shellhunt-job-{job_id}.json"
            },
        )
    @app.get("/reports/<int:job_id>.html")
    def export_html(job_id: int):
        job = db.get_job(job_id)
        if not job:
            abort(404)
        if job["status"] != "done":
            return render_template("error.html", message="report is not ready"), 409
        return Response(report_html(build_report(db, job_id)), mimetype="text/html")
    @app.get("/healthz")
    def healthz():
        return jsonify({"ok": True})
    @app.errorhandler(404)
    def not_found(_error):
        if request.path.startswith("/api/"):
            return jsonify({"error": "not found"}), 404
        return render_template("error.html", message="not found"), 404
    return app
