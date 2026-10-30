"""Blindspot command line."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

from blindspot import __version__
from blindspot.config import ConfigError, load_config, write_starter
from blindspot.dashboard.serve import serve
from blindspot.dashboard.streamlit_app import app_path
from blindspot.db import Database
from blindspot.demo import build_demo
from blindspot.orchestrator import execute, stage_names
from blindspot.report.export import export_case
from blindspot.scope import ScopeManager


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    parser = argparse.ArgumentParser(prog="blindspot", description="Scope-aware black-box reconnaissance case file.")
    parser.add_argument("--version", action="version", version=f"blindspot {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    init_parser = sub.add_parser("init", help="write blindspot.yaml")
    init_parser.add_argument("--dir", default=".")
    init_parser.add_argument("--name", default="engagement")
    init_parser.add_argument("--program", default="Bug bounty program")
    init_parser.set_defaults(func=cmd_init)

    run_parser = sub.add_parser("run", help="run collection and intelligence stages")
    _config_arg(run_parser)
    run_parser.add_argument("--stage", action="append", dest="stages", help="run one stage; repeat to chain stages")
    run_parser.set_defaults(func=cmd_run)

    watch_parser = sub.add_parser("watch", help="run the pipeline on an interval and record changes")
    _config_arg(watch_parser)
    watch_parser.add_argument("--interval", type=int, default=86400)
    watch_parser.add_argument("--iterations", type=int, default=0, help="0 means until interrupted")
    watch_parser.set_defaults(func=cmd_watch)

    jobs_parser = sub.add_parser("jobs", help="list jobs or logs")
    _config_arg(jobs_parser)
    jobs_parser.add_argument("--logs", type=int, default=0)
    jobs_parser.set_defaults(func=cmd_jobs)

    query_parser = sub.add_parser("query", help="print a slice of the case file")
    _config_arg(query_parser)
    query_parser.add_argument(
        "kind",
        choices=["assets", "endpoints", "parameters", "changes", "queue", "events", "relationships", "jobs"],
    )
    query_parser.add_argument("--json", action="store_true")
    query_parser.set_defaults(func=cmd_query)

    scope_parser = sub.add_parser("scope", help="check a host or URL against the config")
    scope_parser.add_argument("action", choices=["check"])
    scope_parser.add_argument("value")
    _config_arg(scope_parser)
    scope_parser.set_defaults(func=cmd_scope)

    report_parser = sub.add_parser("report", help="write JSON, Markdown, lane files, and HTML")
    _config_arg(report_parser)
    report_parser.add_argument("--out", default="")
    report_parser.set_defaults(func=cmd_report)

    serve_parser = sub.add_parser("serve", help="open the local case viewer")
    _config_arg(serve_parser)
    serve_parser.add_argument("--port", type=int, default=8765)
    serve_parser.set_defaults(func=cmd_serve)

    dash_parser = sub.add_parser("dashboard", help="open the optional Streamlit dashboard")
    _config_arg(dash_parser)
    dash_parser.add_argument("--port", type=int, default=8501)
    dash_parser.set_defaults(func=cmd_dashboard)

    demo_parser = sub.add_parser("demo", help="write a fictional offline case you can browse")
    demo_parser.add_argument("--dir", default=".blindspot-demo")
    demo_parser.set_defaults(func=cmd_demo)

    stages_parser = sub.add_parser("stages", help="list stage names")
    stages_parser.set_defaults(func=cmd_stages)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ConfigError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


def cmd_init(args: argparse.Namespace) -> int:
    path = write_starter(Path(args.dir), args.name, args.program)
    print(f"Wrote {path}")
    print("Fill in authorization and scope.include before running.")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    config = _load(args.config)
    _configure_logging()
    summary = asyncio.run(execute(config, only=args.stages))
    print(json.dumps({key: summary[key] for key in ("job_id", "assets", "endpoints", "queued", "changes")}, indent=2))
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    config = _load(args.config)
    _configure_logging()
    iteration = 0
    while True:
        summary = asyncio.run(execute(config))
        print(f"job {summary['job_id']}: {summary['changes']} change(s), {summary['queued']} queued")
        iteration += 1
        if args.iterations and iteration >= args.iterations:
            return 0
        try:
            asyncio.run(asyncio.sleep(args.interval))
        except KeyboardInterrupt:
            return 0


def cmd_jobs(args: argparse.Namespace) -> int:
    config = _load(args.config)
    db = Database(config.database_path())
    try:
        engagement_id = _engagement(db, config)
        if args.logs:
            for row in reversed(db.job_logs(args.logs)):
                print(f"{row['created_at']} {row['level']} {row['message']}")
            return 0
        for row in db.list_jobs(engagement_id):
            print(f"{row['id']} {row['status']} {row['started_at']} {row['selected_stages']}")
    finally:
        db.close()
    return 0


def cmd_query(args: argparse.Namespace) -> int:
    config = _load(args.config)
    db = Database(config.database_path())
    try:
        engagement_id = _engagement(db, config)
        rows = _rows(db, engagement_id, args.kind)
    finally:
        db.close()
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    if not rows:
        print("none")
        return 0
    for row in rows:
        if args.kind == "assets":
            print(f"{row['asset_type']}\t{row['normalized']}\t{row.get('sources') or ''}")
        elif args.kind == "endpoints":
            print(f"{row['functionality']}\t{row['method']} {row['host']}{row['templated_path']}")
        elif args.kind == "parameters":
            print(f"{row['location']}\t{row['name']}\t{row['host']}{row['templated_path']}")
        elif args.kind == "queue":
            print(f"{row['priority']}\t{row.get('confidence_band') or ''}\t{row['status']}\t{row['category']}\t{row['title']}")
        elif args.kind == "changes":
            print(f"{row['change_type']}\t{row['subject']}\t{row['after_value']}")
        elif args.kind == "relationships":
            print(f"{row['src']}\t{row['rel']}\t{row['dst']}")
        else:
            print(json.dumps(row, ensure_ascii=True))
    return 0


def cmd_scope(args: argparse.Namespace) -> int:
    config = _load(args.config)
    scope = ScopeManager.from_lists(config.include, config.exclude)
    value = args.value.strip()
    allowed = scope.allows_url(value) if "://" in value else scope.allows_host(value)
    print("in scope" if allowed else "out of scope")
    return 0 if allowed else 1


def cmd_report(args: argparse.Namespace) -> int:
    config = _load(args.config)
    target = export_case(config, Path(args.out) if args.out else None)
    print(target)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    serve(args.config, args.port)
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    env = os.environ.copy()
    env["BLINDSPOT_CONFIG"] = str(Path(args.config).resolve())
    try:
        import streamlit  # noqa: F401
    except ImportError:
        print("Streamlit is optional. Install it with: python -m pip install -e \".[dashboard]\"", file=sys.stderr)
        print("The built-in viewer is: python -m blindspot serve --config blindspot.yaml", file=sys.stderr)
        return 2
    command = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(app_path()),
        "--server.address",
        "127.0.0.1",
        "--server.port",
        str(args.port),
        "--browser.gatherUsageStats",
        "false",
    ]
    return subprocess.call(command, env=env)


def cmd_demo(args: argparse.Namespace) -> int:
    path = build_demo(Path(args.dir))
    print(path)
    print(f"View it with: python -m blindspot serve --config {path}")
    return 0


def cmd_stages(_args: argparse.Namespace) -> int:
    for name in stage_names():
        print(name)
    return 0


def _config_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", default="blindspot.yaml")


def _load(path: str):
    config = load_config(path)
    config.validate_for_run()
    return config


def _engagement(db: Database, config) -> int:
    return db.ensure_engagement(config.engagement, config.program, config.authorization)


def _rows(db: Database, engagement_id: int, kind: str) -> list[dict]:
    if kind == "assets":
        return db.list_assets(engagement_id)
    if kind == "endpoints":
        return db.list_endpoints(engagement_id)
    if kind == "parameters":
        return db.list_parameters(engagement_id)
    if kind == "changes":
        return db.list_changes(engagement_id)
    if kind == "queue":
        return [row for row in db.list_hypotheses(engagement_id) if row["status"] in {"queued", "accepted"}]
    if kind == "events":
        return db.list_events(engagement_id, limit=200)
    if kind == "relationships":
        return db.list_relationships(engagement_id)
    return db.list_jobs(engagement_id)


def _configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
