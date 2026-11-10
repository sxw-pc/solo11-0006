from __future__ import annotations
import time
from pathlib import Path
from shellhunt.config import Config
from shellhunt.db import Database
from shellhunt.web.routes import create_app
def test_create_poll_report_delete_chain(
    client, config, allowed_root: Path, write_file, wait_for_job
):
    write_file(
        "shell.phps",
        "<?php\neval ( /* $_POST['x'] omitted */ );\n"
        "$out = `<script>alert(1)</script> $_GET['x']`;\n",
        root=allowed_root,
    )
    response = client.post("/api/scans", json={"target": str(allowed_root)})
    assert response.status_code == 202
    job_id = response.get_json()["job_id"]
    assert response.get_json()["status_url"].endswith(f"/api/scans/{job_id}")
    job = wait_for_job(client, job_id)
    assert job["status"] == "done"
    assert job["summary"]["by_verdict"]["malicious"] == 1
    report_response = client.get(f"/api/scans/{job_id}/report")
    assert report_response.status_code == 200
    report = report_response.get_json()
    assert report["schema"] == "shellhunt.report.v1"
    assert report["job"]["id"] == job_id
    assert report["summary"]["total_files"] == 1
    item = report["files"][0]
    assert item["path"] == "shell.phps"
    assert item["verdict"] == "malicious"
    assert item["hits"] and item["signals"] and item["features"] and item["entropy"]
    assert all(len(hit["snippet"]) <= 120 for hit in item["hits"])
    html_response = client.get(f"/reports/{job_id}.html")
    assert html_response.status_code == 200
    body = html_response.get_data(as_text=True)
    assert "<style>" in body and "SELF-CONTAINED OFFLINE REPORT" in body
    assert "&lt;script&gt;" in body
    assert "<script>alert" not in body
    assert "http://" not in body and "https://" not in body
    json_export = client.get(f"/reports/{job_id}.json")
    assert json_export.status_code == 200
    assert "attachment" in json_export.headers["Content-Disposition"]
    delete = client.post(f"/scans/{job_id}/delete")
    assert delete.status_code == 303
    assert client.get(f"/api/scans/{job_id}").status_code == 404
    assert client.get(f"/api/scans/{job_id}/report").status_code == 404
    db = Database(config.db_path)
    assert db.get_file_results(job_id) == []
    assert db.get_hits(job_id) == []
def test_api_rejects_traversal_and_outside_targets(client, allowed_root: Path, tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    targets = [
        str(allowed_root / ".." / "outside"),
        str(outside),
        str(allowed_root / "missing"),
        "",
    ]
    for target in targets:
        response = client.post("/api/scans", json={"target": target})
        assert response.status_code == 400, target
        assert "error" in response.get_json()
def test_api_rejects_unknown_ruleset_and_bad_thresholds(client, allowed_root: Path):
    response = client.post(
        "/api/scans", json={"target": str(allowed_root), "ruleset": "does-not-exist"}
    )
    assert response.status_code == 400
    response = client.post(
        "/api/scans",
        json={"target": str(allowed_root), "suspicious": 70, "malicious": 60},
    )
    assert response.status_code == 400
def test_form_scan_redirects_and_index_renders(
    client, allowed_root: Path, write_file, wait_for_job
):
    write_file("safe.phps", "<?php echo 'safe';", root=allowed_root)
    index = client.get("/")
    assert index.status_code == 200
    assert b"Scan demo site" in index.data
    response = client.post("/scans", data={"target": str(allowed_root), "ruleset": "builtin"})
    assert response.status_code == 303
    job_id = int(response.headers["Location"].rstrip("/").split("/")[-1])
    assert wait_for_job(client, job_id)["status"] == "done"
    page = client.get(f"/scans/{job_id}")
    assert page.status_code == 200
    assert b"safe.phps" in page.data
def test_form_traversal_returns_400(client):
    response = client.post("/scans", data={"target": "../fixtures", "ruleset": "builtin"})
    assert response.status_code == 400
    assert b"path traversal" in response.data.lower()
def test_demo_route_runs_scan(client, config, wait_for_job):
    (config.demo_target / "hello.phps").write_text("<?php echo 'hi';", encoding="utf-8")
    response = client.post("/demo")
    assert response.status_code == 303
    job_id = int(response.headers["Location"].rstrip("/").split("/")[-1])
    job = wait_for_job(client, job_id)
    assert job["status"] == "done"
    assert Path(job["target"]) == config.demo_target
    assert job["summary"]["total_files"] == 1
def test_pending_job_report_is_409(client, config):
    db = Database(config.db_path)
    db.init()
    job_id = db.create_job(str(config.allowed_roots[0]), "builtin", config.thresholds)
    assert client.get(f"/api/scans/{job_id}/report").status_code == 409
    assert client.get(f"/reports/{job_id}.html").status_code == 409
    assert client.get(f"/reports/{job_id}.json").status_code == 409
def test_failed_job_records_error(tmp_path: Path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    config = Config(
        data={
            "database": {"path": str(tmp_path / "failed.db")},
            "security": {"allowed_roots": [str(allowed)], "demo_target": str(allowed)},
            "engine": {
                "rules_dir": str(Path(__file__).resolve().parent.parent / "shellhunt" / "ruleset"),
                "known_bad": str(tmp_path / "missing-known-bad.sha256"),
                "baseline": str(tmp_path / "baseline.json"),
            },
        }
    )
    app = create_app(config=config)
    app.config.update(TESTING=True)
    with app.test_client() as client:
        response = client.post("/api/scans", json={"target": str(allowed)})
        assert response.status_code == 202
        job_id = response.get_json()["job_id"]
        deadline = time.monotonic() + 10
        job = None
        while time.monotonic() < deadline:
            job = client.get(f"/api/scans/{job_id}").get_json()
            if job["status"] == "failed":
                break
            time.sleep(0.02)
        assert job and job["status"] == "failed"
        assert "HashDBError" in job["error"]
        assert client.get(f"/api/scans/{job_id}/report").status_code == 409
def test_api_404s_and_health(client):
    assert client.get("/healthz").get_json() == {"ok": True}
    assert client.get("/api/scans/99999").status_code == 404
    assert client.get("/api/scans").status_code == 200
    assert client.get("/api/unknown").status_code == 404
    assert client.get("/scans/99999").status_code == 404
