#!/usr/bin/env python3
"""shellhunt entry point: Flask service and offline CLI."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from shellhunt.config import Config, ConfigError, TargetValidationError, load_config
from shellhunt.db import Database
from shellhunt.engine.hashdb import generate_baseline
from shellhunt.engine.rules import RuleError, load_ruleset
from shellhunt.engine.scanner import scan_to_database
from shellhunt.web.routes import create_app as _create_app
def create_app(config: Config | None = None, config_path: str | None = None):
    return _create_app(config=config, config_path=config_path)
def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="shellhunt", description=__doc__)
    parser.add_argument("--config", help="path to config.yaml (default: auto-detect)")
    sub = parser.add_subparsers(dest="command")
    serve = sub.add_parser("serve", help="start the local Flask service")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    scan = sub.add_parser("scan", help="scan a directory and persist one job")
    scan.add_argument("target")
    scan.add_argument("--ruleset", help="extra custom rule directory to merge")
    scan.add_argument("--suspicious", type=int)
    scan.add_argument("--malicious", type=int)
    scan.add_argument("--json", action="store_true", help="print the full JSON report")
    baseline = sub.add_parser("baseline", help="write a clean-baseline hash manifest")
    baseline.add_argument("directory")
    baseline.add_argument("--output", default=None)
    sub.add_parser("initdb", help="create the SQLite schema and exit")
    return parser
def command_serve(config: Config, args: argparse.Namespace) -> int:
    app = create_app(config=config)
    host = args.host or config.host
    port = args.port or config.port
    print(f"shellhunt serving on http://{host}:{port} (offline)")
    app.run(host=host, port=port, debug=False, threaded=True)
    return 0
def command_scan(config: Config, args: argparse.Namespace) -> int:
    target = config.validate_target(args.target)
    custom = Path(args.ruleset).resolve() if args.ruleset else None
    ruleset = load_ruleset(config.rules_dir, custom)
    thresholds = {
        "suspicious": args.suspicious if args.suspicious is not None else config.thresholds["suspicious"],
        "malicious": args.malicious if args.malicious is not None else config.thresholds["malicious"],
    }
    if not 0 <= thresholds["suspicious"] < thresholds["malicious"] <= 100:
        raise ConfigError("thresholds must satisfy 0 <= suspicious < malicious <= 100")
    db = Database(config.db_path)
    db.init()
    job_id = db.create_job(str(target), custom.name if custom else "builtin", thresholds)
    db.mark_running(job_id)
    try:
        report = scan_to_database(config, db, job_id, target, ruleset, thresholds)
    except Exception as exc:  # noqa: BLE001
        db.fail_job(job_id, f"{type(exc).__name__}: {exc}")
        raise
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    summary = report["summary"]
    counts = summary["by_verdict"]
    print(f"job #{job_id}: {target}")
    print(
        f"files={summary['total_files']} malicious={counts['malicious']} "
        f"suspicious={counts['suspicious']} clean={counts['clean']} "
        f"rule_hits={summary['total_hits']} skipped={summary['skipped']}"
    )
    for item in summary["top_risk"][:8]:
        print(f"  {item['score']:3d}  {item['verdict']:<10}  {item['path']}")
    print(f"HTML report: /reports/{job_id}.html after `python app.py serve`")
    return 0
def command_baseline(config: Config, args: argparse.Namespace) -> int:
    target = config.validate_target(args.directory)
    output = Path(args.output).expanduser().resolve() if args.output else config.baseline_path
    count = generate_baseline(
        target, output, config.extensions, config.max_file_size
    )
    print(f"baseline: {count} file(s) from {target}")
    print(f"written: {output}")
    return 0
def command_initdb(config: Config, _args: argparse.Namespace) -> int:
    db = Database(config.db_path)
    db.init()
    print(f"initialized database: {config.db_path}")
    return 0
def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        config = load_config(args.config)
        command = args.command or "serve"
        if command == "serve":
            if args.command is None:
                args.host = getattr(args, "host", None)
                args.port = getattr(args, "port", None)
            return command_serve(config, args)
        if command == "scan":
            return command_scan(config, args)
        if command == "baseline":
            return command_baseline(config, args)
        if command == "initdb":
            return command_initdb(config, args)
        raise ConfigError(f"unknown command: {command}")
    except (ConfigError, TargetValidationError, RuleError, OSError) as exc:
        print(f"shellhunt: {exc}", file=sys.stderr)
        return 2
if __name__ == "__main__":
    raise SystemExit(main())
