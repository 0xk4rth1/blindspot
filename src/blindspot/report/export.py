"""Read models shared by the HTML case file and the export pack."""

from __future__ import annotations

import json
from pathlib import Path

from blindspot.config import AppConfig
from blindspot.db import Database


def case_payload(db: Database, engagement_id: int) -> dict:
    engagement = db.engagement_row(engagement_id)
    jobs = db.list_jobs(engagement_id)
    logs = db.job_logs(jobs[0]["id"], limit=40) if jobs else []
    hypotheses = db.list_hypotheses(engagement_id)
    return {
        "engagement": {
            "id": engagement["id"],
            "name": engagement["name"],
            "program": engagement["program"],
            "authorization": engagement["authorization"],
            "created_at": engagement["created_at"],
        },
        "summary": db.summary(engagement_id),
        "assets": db.list_assets(engagement_id),
        "endpoints": db.list_endpoints(engagement_id),
        "parameters": db.list_parameters(engagement_id),
        "relationships": db.list_relationships(engagement_id),
        "technologies": db.list_technologies(engagement_id),
        "surface": db.list_surface(engagement_id, limit=500),
        "changes": db.list_changes(engagement_id)[:200],
        "hypotheses": hypotheses,
        "jobs": jobs[:12],
        "logs": logs,
    }


def discovery_payload(db: Database, engagement_id: int) -> dict:
    """Hosts and counts for the project page. Small enough to read while discovery is writing."""

    engagement = db.engagement_row(engagement_id)
    summary = db.summary(engagement_id)
    hosts = db.live_hosts(engagement_id, limit=400)
    return {
        "engagement": {
            "id": engagement["id"],
            "name": engagement["name"],
            "program": engagement["program"],
            "authorization": engagement["authorization"],
            "created_at": engagement["created_at"],
        },
        "summary": summary,
        "assets": [
            {
                "asset_type": "host",
                "normalized": host,
                "in_scope": 1,
                "active": 1,
                "sources": "",
                "first_seen": "",
                "last_seen": "",
            }
            for host in hosts
        ],
        "assets_truncated": int(summary.get("live_hosts") or 0) > len(hosts),
        "endpoints": [],
        "parameters": [],
        "relationships": [],
        "technologies": [],
        "surface": [],
        "changes": [],
        "hypotheses": [],
        "jobs": [],
        "logs": [],
        "busy": False,
    }


def safe_json(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=True).replace("<", "\\u003c")


def export_case(config: AppConfig, directory: Path | None = None, *, create: bool = True) -> Path:
    db = Database(config.database_path(), readonly=not create)
    try:
        engagement_id = db.find_engagement(config.engagement)
        if engagement_id is None and create:
            db.close()
            db = Database(config.database_path())
            engagement_id = db.ensure_engagement(config.engagement, config.program, config.authorization)
        if engagement_id is None:
            return directory or config.report_dir()
        payload = case_payload(db, engagement_id)
        events = db.list_events(engagement_id, limit=2000)
        hosts = db.live_hosts(engagement_id)
    finally:
        db.close()
    target = directory or (config.report_dir() / config.engagement)
    target.mkdir(parents=True, exist_ok=True)
    (target / "case.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _jsonl(target / "events.jsonl", events)
    lanes = target / "lanes"
    lanes.mkdir(exist_ok=True)
    _lines(lanes / "hosts.txt", hosts)
    _lines(
        lanes / "endpoints.txt",
        [f"{row['method']} {row['host']}{row['templated_path']}" for row in payload["endpoints"]],
    )
    _lines(
        lanes / "parameters.txt",
        [f"{row['location']} {row['name']} {row['host']}{row['templated_path']}" for row in payload["parameters"]],
    )
    (target / "report.md").write_text(_markdown(payload), encoding="utf-8")
    from blindspot.dashboard.page import render_page

    (target / "report.html").write_text(render_page(safe_json(payload)), encoding="utf-8")
    return target


def export_hosts(config: AppConfig) -> None:
    """Rewrite hosts.txt during discovery without building the full report."""

    import sqlite3

    db = Database(config.database_path(), readonly=True, timeout=2)
    try:
        engagement_id = db.find_engagement(config.engagement)
        if engagement_id is None:
            return
        hosts = db.live_hosts(engagement_id)
    except sqlite3.OperationalError:
        return
    finally:
        db.close()
    lanes = config.report_dir() / "lanes"
    lanes.mkdir(parents=True, exist_ok=True)
    _lines(lanes / "hosts.txt", hosts)


def _jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")


def _lines(path: Path, values: list[str]) -> None:
    unique = []
    seen = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            unique.append(value)
    path.write_text("\n".join(unique) + ("\n" if unique else ""), encoding="utf-8")


def _markdown(payload: dict) -> str:
    engagement = payload["engagement"]
    summary = payload["summary"]
    lines = [
        f"# Blindspot case: {engagement['name']}",
        "",
        engagement["program"],
        "",
        f"Authorization: {engagement['authorization']}",
        "",
        "Hypotheses are review prompts with evidence. They are not confirmed findings.",
        "",
        "## Counts",
        "",
    ]
    for key, value in summary.items():
        lines.append(f"- {key}: {value}")
    lines.extend(["", "## Functionality", ""])
    grouped: dict[str, list[str]] = {}
    for row in payload["endpoints"]:
        grouped.setdefault(row["functionality"], []).append(
            f"{row['method']} {row['host']}{row['templated_path']} ({row['classification']})"
        )
    if not grouped:
        lines.append("No endpoints classified yet.")
    for name, items in sorted(grouped.items()):
        lines.append(f"### {name}")
        lines.append("")
        for item in items[:40]:
            lines.append(f"- {item}")
        lines.append("")
    lines.extend(["## Investigation queue", ""])
    queued = [row for row in payload["hypotheses"] if row["status"] in {"queued", "accepted"}]
    if not queued:
        lines.append("Queue is empty.")
    for row in queued[:40]:
        lines.append(f"### {row['priority']} · {row['title']}")
        lines.append("")
        lines.append(row["summary"])
        lines.append("")
        band = row.get("confidence_band") or "supported"
        lines.append(f"Status: {row['status']}. Band: {band}. Confidence: {row['confidence']}.")
        if row.get("rationale"):
            lines.append("")
            lines.append(f"Why: {row['rationale']}")
        if row.get("limitations"):
            lines.append("")
            lines.append(f"Limitations: {row['limitations']}")
        if row.get("validation_steps"):
            lines.append("")
            lines.append(f"Manual review: {row['validation_steps']}")
        observations = row.get("observations") or []
        if observations:
            lines.append("")
            lines.append("Evidence:")
            for item in observations[:8]:
                marker = f"#{item['event_id']} " if item.get("event_id") else ""
                lines.append(f"- {marker}{item.get('kind', '')} {item.get('value', '')}".rstrip())
        lines.append("")
    lines.extend(["## Changes", ""])
    if not payload["changes"]:
        lines.append("No changes recorded.")
    for row in payload["changes"][:40]:
        lines.append(
            f"- {row['change_type']}: {row['subject']} {row['before_value']} -> {row['after_value']}".rstrip()
        )
    lines.append("")
    return "\n".join(lines)
