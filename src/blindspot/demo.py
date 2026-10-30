"""Offline fictional case so the viewer can be opened without collecting anything."""

from __future__ import annotations

import asyncio
from pathlib import Path

from blindspot.config import load_config
from blindspot.db import Database
from blindspot.intelligence.engine import ChangeDetectStage, ClassifyStage, CorrelateStage, HypothesizeStage
from blindspot.intake import Intake

_YAML = """\
engagement: northwind
program: "Northwind fictional program"
authorization: "Authorized fictional demonstration case. No network collection."
network:
  enabled: false
seeds:
  - https://app.northwind.test
scope:
  include:
    - northwind.test
    - "*.northwind.test"
  exclude:
    - payments.northwind.test
limits:
  request_delay_ms: 0
tools:
  subfinder:
    enabled: false
  amass:
    enabled: false
  dnsx:
    enabled: false
  httpx:
    enabled: false
  katana:
    enabled: false
  gau:
    enabled: false
output:
  database: case.sqlite
  report_dir: reports
"""


def build_demo(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    config_path = directory / "blindspot.yaml"
    config_path.write_text(_YAML, encoding="utf-8")
    config = load_config(config_path)
    config.validate_for_run()
    db = Database(config.database_path())
    try:
        engagement_id = db.ensure_engagement(config.engagement, config.program, config.authorization)
        scope = config.scope()
        db.replace_scope(engagement_id, scope.rules)
        job_id = db.create_job(engagement_id, ["demo"])
        intake = Intake(db, scope, engagement_id, job_id, config.limits.max_urls)
        intake.host("app.northwind.test", source="seed", confidence=1.0, evidence="seed")
        intake.host("admin.northwind.test", source="ct_logs", confidence=0.7, evidence="certificate")
        intake.host("staging.northwind.test", source="js_analysis", confidence=0.45, evidence="app.js")
        intake.external(
            "app.northwind.test",
            "spf_includes",
            "_spf.google.com",
            source="dns_resolve",
            evidence="SPF include",
        )
        intake.external(
            "app.northwind.test",
            "script_src",
            "cdn.example",
            source="http_probe",
            evidence="script src",
        )
        intake.surface(
            "https://app.northwind.test/admin/export",
            source="crawl",
            confidence=0.7,
            status=200,
        )
        intake.surface(
            "https://app.northwind.test/legacy/report",
            source="wayback",
            confidence=0.55,
            status=200,
            observed_at="2019-04-01T00:00:00+00:00",
        )
        intake.surface(
            "https://app.northwind.test/api/users",
            source="js_analysis",
            confidence=0.6,
            status=200,
        )
        intake.parameter("app.northwind.test", "/login", "redirect", "form", "http_probe")
        intake.parameter("app.northwind.test", "/api/users", "id", "query", "js_analysis")
        intake.event(
            source="js_analysis",
            kind="credential_pattern",
            subject="https://app.northwind.test/app.js",
            value="aws_access_key_id",
            confidence=0.7,
            evidence="https://app.northwind.test/app.js",
            meta={"fingerprint": "demo-fingerprint"},
        )
        intake.event(
            source="js_analysis",
            kind="sourcemap_url",
            subject="https://app.northwind.test/app.js",
            value="https://app.northwind.test/app.js.map",
            confidence=0.8,
            evidence="https://app.northwind.test/app.js",
        )
        intake.event(
            source="sourcemap",
            kind="source_path",
            subject="https://app.northwind.test/app.js.map",
            value="src/admin/Export.ts",
            confidence=0.75,
            evidence="https://app.northwind.test/app.js.map",
        )
        intake.event(
            source="js_analysis",
            kind="feature_flag",
            subject="app.northwind.test",
            value="newBilling",
            confidence=0.5,
            evidence="https://app.northwind.test/app.js",
        )
        intake.event(
            source="js_analysis",
            kind="js_endpoint",
            subject="app.northwind.test",
            value="/api/users",
            confidence=0.6,
            evidence="https://app.northwind.test/app.js",
        )
        intake.event(
            source="openapi",
            kind="api_operation",
            subject="app.northwind.test",
            value="POST /admin/export",
            confidence=0.85,
            evidence="https://app.northwind.test/openapi.json",
            meta={"method": "POST", "path": "/admin/export", "security": [], "parameters": []},
        )
        db.upsert_technology(
            engagement_id, host="app.northwind.test", name="nginx", version="1.18.0", source="http_probe", confidence=0.8
        )
        db.upsert_technology(
            engagement_id, host="app.northwind.test", name="nginx", version="1.25.1", source="http_probe", confidence=0.8
        )
        ctx = type("Ctx", (), {})()
        ctx.db = db
        ctx.engagement_id = engagement_id
        ctx.job_id = job_id
        ctx.selected_stages = ["demo"]
        asyncio.run(_finish(ctx))
        db.finish_job(job_id, "completed", stats={"demo": True})
    finally:
        db.close()
    return config_path


async def _finish(ctx) -> None:
    await ClassifyStage().execute(ctx)
    await CorrelateStage().execute(ctx)
    await ChangeDetectStage().execute(ctx)
    await HypothesizeStage().execute(ctx)
