"""Intelligence is read-only over the case file. It does not fetch or attack."""

from __future__ import annotations

from blindspot.parsekit import classify_endpoint, is_sensitive_parameter
from blindspot.stages.result import StageResult

WEIGHTS = {
    "exposed_secret_pattern": 92,
    "unauthenticated_admin_spec": 88,
    "admin_surface": 78,
    "sensitive_parameter": 76,
    "source_map": 74,
    "cors_posture": 62,
    "graphql": 64,
    "new_asset": 58,
    "retired_surface": 52,
    "client_only_host": 50,
    "trust_boundary": 44,
    "session_cookie": 40,
    "feature_exposure": 36,
    "tech_change": 30,
}

LIVE_SOURCES = {"http_probe", "httpx", "crawl", "katana", "link", "js_analysis", "openapi", "seed"}
HISTORICAL_SOURCES = {"wayback", "commoncrawl", "urlscan", "gau"}
TRUST_RELS = {"spf_includes", "cname", "script_src", "redirect", "csp_allows"}


def priority_for(category: str, confidence: float) -> int:
    weight = WEIGHTS.get(category, 40)
    bounded = max(0.0, min(1.0, confidence))
    return int(round(weight * (0.55 + 0.45 * bounded)))


class ChangeDetectStage:
    name = "change_detect"

    async def execute(self, ctx) -> StageResult:
        stages = set(ctx.selected_stages)
        count = ctx.db.detect_changes(ctx.engagement_id, ctx.job_id, stages)
        return StageResult(self.name, inserted=count)


class ClassifyStage:
    name = "classify"

    async def execute(self, ctx) -> StageResult:
        inserted = 0
        parameters = ctx.db.list_parameters(ctx.engagement_id)
        by_path: dict[tuple[str, str], list[str]] = {}
        for row in parameters:
            by_path.setdefault((row["host"], row["templated_path"]), []).append(row["name"])
        seen: set[tuple[str, str, str]] = set()
        for row in ctx.db.list_surface(ctx.engagement_id):
            key = (row["host"], row["method"], row["templated_path"])
            if key in seen:
                continue
            seen.add(key)
            names = by_path.get((row["host"], row["templated_path"]), [])
            classification, functionality = classify_endpoint(row["templated_path"], names)
            ctx.db.upsert_endpoint(
                ctx.engagement_id,
                host=row["host"],
                method=row["method"],
                templated=row["templated_path"],
                classification=classification,
                functionality=functionality,
                source=row["last_source"],
            )
            inserted += 1
        for event in ctx.db.list_events(ctx.engagement_id, kind="js_endpoint", limit=1000):
            host = event["subject"]
            path = event["value"]
            names = by_path.get((host, path), [])
            classification, functionality = classify_endpoint(path, names)
            ctx.db.upsert_endpoint(
                ctx.engagement_id,
                host=host,
                method="GET",
                templated=path,
                classification=classification,
                functionality=functionality,
                source="js_analysis",
            )
            inserted += 1
        return StageResult(self.name, inserted=inserted)


class CorrelateStage:
    name = "correlate"

    async def execute(self, ctx) -> StageResult:
        inserted = 0
        for endpoint in ctx.db.list_endpoints(ctx.engagement_id):
            ctx.db.upsert_relationship(
                ctx.engagement_id,
                src=endpoint["host"],
                rel="serves",
                dst=f"{endpoint['method']} {endpoint['templated_path']}",
                source=self.name,
                in_scope_dst=True,
            )
            inserted += 1
        for tech in ctx.db.list_technologies(ctx.engagement_id):
            label = tech["name"] if not tech["version"] else f"{tech['name']} {tech['version']}"
            ctx.db.upsert_relationship(
                ctx.engagement_id,
                src=tech["host"],
                rel="technology",
                dst=label,
                source=self.name,
                evidence=tech["source"],
                in_scope_dst=False,
            )
            inserted += 1
        for parameter in ctx.db.list_parameters(ctx.engagement_id):
            ctx.db.upsert_relationship(
                ctx.engagement_id,
                src=f"{parameter['host']}{parameter['templated_path']}",
                rel="parameter",
                dst=f"{parameter['location']}:{parameter['name']}",
                source=self.name,
                in_scope_dst=True,
            )
            inserted += 1
        return StageResult(self.name, inserted=inserted)


class HypothesizeStage:
    name = "hypothesize"

    async def execute(self, ctx) -> StageResult:
        drafts = build_hypotheses(ctx.db, ctx.engagement_id)
        for draft in drafts:
            ctx.db.upsert_hypothesis(ctx.engagement_id, **draft)
        return StageResult(self.name, inserted=len(drafts))


def build_hypotheses(db, engagement_id: int) -> list[dict]:
    drafts: list[dict] = []
    endpoints = db.list_endpoints(engagement_id)
    parameters = db.list_parameters(engagement_id)
    assets = db.list_assets(engagement_id)
    relationships = db.list_relationships(engagement_id)
    changes = db.list_changes(engagement_id)
    operations = {
        event["value"]: event
        for event in db.list_events(engagement_id, kind="api_operation", limit=1000)
    }

    for event in db.list_events(engagement_id, kind="api_operation", limit=500):
        meta = event["meta"] or {}
        path = str(meta.get("path") or "")
        method = str(meta.get("method") or "GET")
        security = meta.get("security")
        names = [item.get("name", "") for item in meta.get("parameters") or [] if isinstance(item, dict)]
        classification, _functionality = classify_endpoint(path, names)
        subject = f"{method} {event['subject']}{path}"
        if classification == "admin" and security == []:
            drafts.append(
                _draft(
                    "unauthenticated_admin_spec",
                    subject,
                    subject,
                    "API spec lists an admin operation without a security scheme",
                    "The API specification describes an administrative operation without a security scheme. "
                    "Confirm whether the live operation requires authorization.",
                    0.8,
                    [{"spec": event["evidence"], "operation": event["value"]}],
                )
            )

    for event in db.list_events(engagement_id, kind="credential_pattern", limit=100):
        pattern = event["value"]
        drafts.append(
            _draft(
                "exposed_secret_pattern",
                f"{pattern}:{event['subject']}",
                event["subject"],
                f"Public response matches a {pattern} pattern",
                "A public response matches a credential-like pattern. "
                "The value was not stored. Confirm it in the referenced file and report it if it is real.",
                0.7,
                [{"source": event["source"], "subject": event["subject"], "pattern": pattern}],
            )
        )

    for endpoint in endpoints:
        subject = f"{endpoint['method']} {endpoint['host']}{endpoint['templated_path']}"
        operation = operations.get(f"{endpoint['method']} {endpoint['templated_path']}")
        security = (operation or {}).get("meta", {}).get("security") if operation else None
        if endpoint["classification"] == "admin":
            if operation is not None and security == []:
                drafts.append(
                    _draft(
                        "unauthenticated_admin_spec",
                        subject,
                        subject,
                        "API spec lists an admin operation without a security scheme",
                        "The API specification describes an administrative operation without a security scheme. "
                        "Confirm whether the live operation requires authorization.",
                        0.8,
                        [{"spec": operation["evidence"], "operation": operation["value"]}],
                    )
                )
            else:
                drafts.append(
                    _draft(
                        "admin_surface",
                        subject,
                        subject,
                        "Administrative path observed",
                        "An endpoint was classified as administrative from its path or specification. "
                        "Review whether it is intended to be reachable and how authorization is enforced.",
                        0.6,
                        [{"path": endpoint["templated_path"], "sources": endpoint["sources"]}],
                    )
                )
        if endpoint["classification"] == "graphql":
            drafts.append(
                _draft(
                    "graphql",
                    subject,
                    subject,
                    "GraphQL endpoint observed",
                    "A GraphQL endpoint was observed. Review authentication and which operations are exposed.",
                    0.6,
                    [{"path": endpoint["templated_path"]}],
                )
            )

    for parameter in parameters:
        if not is_sensitive_parameter(parameter["name"]):
            continue
        subject = f"{parameter['host']}{parameter['templated_path']}?{parameter['name']}"
        drafts.append(
            _draft(
                "sensitive_parameter",
                subject,
                subject,
                f"Parameter {parameter['name']} needs manual review",
                f"Parameter '{parameter['name']}' belongs to a name class such as redirect, file, url, "
                "template, or callback. Review how the application uses it.",
                0.55,
                [{"location": parameter["location"], "source": parameter["source"]}],
            )
        )

    maps = db.list_events(engagement_id, kind="sourcemap_url", limit=50)
    paths = db.list_events(engagement_id, kind="source_path", limit=100)
    if maps or paths:
        subject = maps[0]["value"] if maps else paths[0]["subject"]
        listed = [row["value"] for row in paths[:8]]
        drafts.append(
            _draft(
                "source_map",
                subject,
                subject,
                "JavaScript source map is publicly referenced",
                "A JavaScript source map is publicly referenced. Review the listed source paths. "
                "File contents were not copied into this case.",
                0.8,
                [{"paths": listed}],
            )
        )

    for event in db.list_events(engagement_id, kind="http_snapshot", limit=300):
        acao = str((event["meta"] or {}).get("acao") or "")
        acac = str((event["meta"] or {}).get("acac") or "").lower()
        if acao == "*" and acac in {"true", "1"}:
            drafts.append(
                _draft(
                    "cors_posture",
                    event["subject"],
                    event["subject"],
                    "CORS allows any origin with credentials",
                    "A response allows any origin and also allows credentials. "
                    "Review whether that combination is intentional.",
                    0.75,
                    [{"acao": acao, "acac": acac}],
                )
            )

    for event in db.list_events(engagement_id, kind="cookie_flag", limit=200):
        meta = event["meta"] or {}
        name = str(meta.get("name") or event["value"]).lower()
        if meta.get("httponly"):
            continue
        if not any(token in name for token in ("session", "sid", "auth", "token")):
            continue
        drafts.append(
            _draft(
                "session_cookie",
                f"{event['subject']}:{event['value']}",
                event["subject"],
                f"Cookie {event['value']} has no HttpOnly flag",
                "A cookie whose name looks session-related was set without HttpOnly. "
                "Review the cookie flags. The cookie value was not stored.",
                0.6,
                [{"secure": meta.get("secure"), "samesite": meta.get("samesite")}],
            )
        )

    for change in changes:
        if change["change_type"] == "added" and change["subject"].startswith("domain:"):
            host = change["after_value"]
            drafts.append(
                _draft(
                    "new_asset",
                    change["subject"],
                    host,
                    f"New host {host}",
                    f"Host {host} was first recorded in this case. Review what it exposes.",
                    0.65,
                    [{"change": change["change_type"]}],
                )
            )
        if change["change_type"] == "modified" and change["subject"].startswith("technology:"):
            drafts.append(
                _draft(
                    "tech_change",
                    change["subject"],
                    change["subject"],
                    "Technology fingerprint changed",
                    "An observed technology fingerprint changed between versions stored in this case. "
                    f"Earlier value '{change['before_value']}', later value '{change['after_value']}'.",
                    0.6,
                    [{"before": change["before_value"], "after": change["after_value"]}],
                )
            )

    for row in db.list_surface(engagement_id, limit=1000):
        if row["first_source"] in HISTORICAL_SOURCES and row["last_source"] in HISTORICAL_SOURCES:
            subject = f"{row['host']}{row['templated_path']}"
            drafts.append(
                _draft(
                    "retired_surface",
                    subject,
                    subject,
                    "Historical URL not seen in the current collection",
                    "This path appears in a historical source and was not recorded by the current "
                    "probe or crawl. Compare it with the live application before spending time on it.",
                    0.5,
                    [{"first_source": row["first_source"], "last_source": row["last_source"]}],
                )
            )

    for asset in assets:
        sources = set((asset.get("sources") or "").split(","))
        if "js_analysis" in sources and not sources.intersection({"dns_resolve", "http_probe", "httpx", "seed"}):
            drafts.append(
                _draft(
                    "client_only_host",
                    asset["normalized"],
                    asset["normalized"],
                    f"{asset['normalized']} is referenced from client code",
                    "This in-scope hostname is referenced from client-side code and has no DNS or HTTP "
                    "observation yet. Decide whether it belongs in a later authorized pass.",
                    0.45,
                    [{"sources": sorted(sources)}],
                )
            )

    trust_count = 0
    for relation in relationships:
        if relation["rel"] not in TRUST_RELS or relation["in_scope_dst"]:
            continue
        if trust_count >= 15:
            break
        trust_count += 1
        subject = f"{relation['src']} {relation['rel']} {relation['dst']}"
        drafts.append(
            _draft(
                "trust_boundary",
                subject,
                relation["src"],
                f"{relation['src']} depends on {relation['dst']}",
                f"The in-scope name depends on external name {relation['dst']} via {relation['rel']}. "
                "Review that trust boundary manually. The external name was not scanned.",
                0.55,
                [{"rel": relation["rel"], "dst": relation["dst"], "source": relation["source"]}],
            )
        )

    flags_by_host: dict[str, list[str]] = {}
    for event in db.list_events(engagement_id, kind="feature_flag", limit=200):
        flags_by_host.setdefault(event["subject"], []).append(event["value"])
    for host, flags in flags_by_host.items():
        shown = ", ".join(flags[:8])
        drafts.append(
            _draft(
                "feature_exposure",
                host,
                host,
                "Client code names feature flags",
                f"Client code exposes feature flag names ({shown}). "
                "Review whether unfinished functionality is meant to be reachable.",
                0.45,
                [{"flags": flags[:8]}],
            )
        )

    unique: list[dict] = []
    seen: set[str] = set()
    for draft in drafts:
        if draft["dedupe_key"] in seen:
            continue
        seen.add(draft["dedupe_key"])
        unique.append(draft)
    return unique[:200]


def _draft(
    category: str,
    dedupe_key: str,
    subject: str,
    title: str,
    summary: str,
    confidence: float,
    evidence: list[dict],
) -> dict:
    return {
        "dedupe_key": f"{category}:{dedupe_key}",
        "title": title,
        "category": category,
        "subject": subject,
        "summary": summary,
        "priority": priority_for(category, confidence),
        "confidence": confidence,
        "evidence": evidence,
    }
