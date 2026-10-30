"""Runs stages in order and records a job around them."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from blindspot.adapters.external import ToolRunner, default_tool_runner
from blindspot.config import AppConfig
from blindspot.db import Database
from blindspot.gate import RequestAudit, alias_block_reason
from blindspot.http_client import ProviderHttp, TargetHttp, provider_origins
from blindspot.http_client import Transport
from blindspot.intake import Intake
from blindspot.intelligence.engine import ChangeDetectStage, ClassifyStage, CorrelateStage, HypothesizeStage
from blindspot.normalize import host_from_url, is_http_url
from blindspot.stages.appintel import CrawlStage, JavaScriptStage, OpenApiStage, SourceMapStage
from blindspot.stages.names import AmassStage, SubfinderStage
from blindspot.stages.passive import CertificateTransparencyStage, DnsStage
from blindspot.stages.result import StageResult
from blindspot.stages.web import CommonCrawlStage, FingerprintStage, GauStage, HttpProbeStage, UrlscanStage, WaybackStage

logger = logging.getLogger("blindspot")

STAGE_ORDER = [
    SubfinderStage(),
    AmassStage(),
    CertificateTransparencyStage(),
    DnsStage(),
    HttpProbeStage(),
    FingerprintStage(),
    WaybackStage(),
    CommonCrawlStage(),
    UrlscanStage(),
    GauStage(),
    CrawlStage(),
    JavaScriptStage(),
    SourceMapStage(),
    OpenApiStage(),
    ChangeDetectStage(),
    ClassifyStage(),
    CorrelateStage(),
    HypothesizeStage(),
]


class RunLog:
    def __init__(self, db: Database, job_id: int):
        self.db = db
        self.job_id = job_id

    def info(self, message: str) -> None:
        logger.info(message)
        self.db.add_log(self.job_id, "info", message)

    def warning(self, message: str) -> None:
        logger.warning(message)
        self.db.add_log(self.job_id, "warning", message)

    def error(self, message: str) -> None:
        logger.error(message)
        self.db.add_log(self.job_id, "error", message)


@dataclass
class RunContext:
    config: AppConfig
    db: Database
    scope: object
    job_id: int
    engagement_id: int
    intake: Intake
    target_http: TargetHttp
    provider_http: ProviderHttp
    log: RunLog
    tool_runner: ToolRunner
    selected_stages: list[str]


def stage_names() -> list[str]:
    return [stage.name for stage in STAGE_ORDER]


async def execute(
    config: AppConfig,
    *,
    only: list[str] | None = None,
    transport: Transport | None = None,
    tool_runner: ToolRunner | None = None,
) -> dict:
    config.validate_for_run()
    scope = config.scope()
    scope.assert_seeds(config.seeds)
    selected = _select(only)
    db = Database(config.database_path())
    try:
        engagement_id = db.ensure_engagement(config.engagement, config.program, config.authorization)
        db.replace_scope(engagement_id, scope.rules)
        job_id = db.create_job(engagement_id, [stage.name for stage in selected])
        db.apply_scope(engagement_id, scope, job_id)
        intake = Intake(db, scope, engagement_id, job_id, config.limits.max_urls)
        audit = RequestAudit(db, engagement_id, job_id)
        intake.auditor = audit

        def guard(url: str) -> str:
            host = host_from_url(url)
            return alias_block_reason(scope, host, db.list_relationships(engagement_id))

        _seed(intake, config.seeds)
        log = RunLog(db, job_id)
        provider_cap = max(config.limits.max_body_bytes, 2_000_000)
        ctx = RunContext(
            config=config,
            db=db,
            scope=scope,
            job_id=job_id,
            engagement_id=engagement_id,
            intake=intake,
            target_http=TargetHttp(
                scope,
                timeout=config.limits.timeout_seconds,
                delay_ms=config.limits.request_delay_ms,
                max_bytes=config.limits.max_body_bytes,
                network_enabled=config.network.enabled,
                transport=transport,
                guard=guard,
                auditor=audit,
            ),
            provider_http=ProviderHttp(
                provider_origins(
                    config.providers.doh,
                    config.providers.crtsh,
                    config.providers.wayback,
                    config.providers.commoncrawl_collinfo,
                    config.providers.urlscan,
                ),
                timeout=config.limits.timeout_seconds,
                delay_ms=config.limits.request_delay_ms,
                max_bytes=provider_cap,
                network_enabled=config.network.enabled,
                transport=transport,
                auditor=audit,
            ),
            log=log,
            tool_runner=tool_runner or default_tool_runner,
            selected_stages=[stage.name for stage in selected],
        )
        # Common Crawl's cdx-api host is the collinfo host for the public index.
        # A collection document may name another origin; that origin is allowlisted
        # only when the operator set commoncrawl_collinfo to it, or when it matches
        # an origin already configured. Tests point collinfo at the fixture host,
        # and the fixture's cdx-api uses that same host.
        results: list[dict] = []
        for stage in selected:
            audit.stage = stage.name
            log.info(f"stage start {stage.name}")
            try:
                result: StageResult = await stage.execute(ctx)
            except Exception as exc:
                log.error(f"stage {stage.name} failed: {exc}")
                results.append({"name": stage.name, "error": str(exc)})
                continue
            log.info(
                f"stage done {stage.name} inserted={result.inserted} skipped={result.skipped} {result.note}".rstrip()
            )
            results.append({"name": result.name, "inserted": result.inserted, "note": result.note})
        _notify(db, config, engagement_id, job_id)
        db.finish_job(job_id, "completed", stats={"stages": results, "dropped": intake.dropped})
        summary = db.summary(engagement_id)
        summary["job_id"] = job_id
        summary["stages"] = results
        return summary
    finally:
        db.close()


def _select(only: list[str] | None) -> list:
    if not only:
        return list(STAGE_ORDER)
    by_name = {stage.name: stage for stage in STAGE_ORDER}
    unknown = [name for name in only if name not in by_name]
    if unknown:
        known = ", ".join(by_name)
        raise ValueError(f"unknown stage: {', '.join(unknown)}. Known stages: {known}")
    return [by_name[name] for name in only]


def _seed(intake: Intake, seeds: list[str]) -> None:
    for seed in seeds:
        if is_http_url(seed):
            intake.host(host_from_url(seed), source="seed", confidence=1.0, evidence="seed")
            intake.surface(seed, source="seed", confidence=1.0, evidence="seed")
        else:
            intake.host(seed, source="seed", confidence=1.0, evidence="seed")


def _notify(db: Database, config: AppConfig, engagement_id: int, job_id: int) -> None:
    changes = db.list_changes(engagement_id, job_id=job_id)
    if not changes:
        return
    payload = {
        "engagement": config.engagement,
        "job_id": job_id,
        "count": len(changes),
        "changes": [
            {"type": row["change_type"], "subject": row["subject"], "after": row["after_value"]}
            for row in changes[:40]
        ],
    }
    message = f"{len(changes)} change(s) recorded for {config.engagement}"
    db.add_notification(engagement_id, job_id, message, payload)
    report_dir = config.report_dir()
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / "notifications.jsonl"
    import json

    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload) + "\n")
    webhook = config.notify.webhook.strip()
    if not webhook or not config.network.enabled:
        return
    _post_webhook(webhook, payload)


def _post_webhook(url: str, payload: dict) -> None:
    from urllib.parse import urlsplit
    from urllib.request import Request, urlopen
    import json

    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    allowed = parts.scheme == "https" or (
        parts.scheme == "http" and host in {"127.0.0.1", "localhost", "::1"}
    )
    if not allowed:
        logger.warning("webhook must be https, or http on localhost")
        return
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=10) as response:
            response.read(1024)
    except Exception as exc:
        logger.warning("webhook failed: %s", exc)
