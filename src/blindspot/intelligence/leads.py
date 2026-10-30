"""Build fewer leads, each tied to the observations that support it.

A lead is a review prompt. It is not a confirmed finding and it does not
include a reproduction procedure.
"""

from __future__ import annotations

import re
from collections import defaultdict

from blindspot.parsekit import classify_endpoint, is_sensitive_parameter

LIVE_SOURCES = {"http_probe", "httpx", "crawl", "katana", "link", "js_analysis", "openapi", "seed"}
HISTORICAL_SOURCES = {"wayback", "commoncrawl", "urlscan", "gau"}
BAND_CEILING = {"speculative": 45, "supported": 75, "strong": 100}
WEIGHTS = {
    "exposed_secret_pattern": 92,
    "unauthenticated_admin_spec": 88,
    "tenant_boundary": 84,
    "sensitive_parameter": 76,
    "source_map": 74,
    "client_bundle": 70,
    "historical_functionality": 64,
    "cors_posture": 62,
    "graphql": 60,
    "admin_surface": 58,
    "client_only_host": 48,
    "trust_boundary": 46,
    "tech_change": 40,
    "new_asset": 36,
    "session_cookie": 34,
}
_VERSION = re.compile(r"^v\d+$", re.I)


def priority_for(category: str, confidence: float, band: str) -> int:
    weight = WEIGHTS.get(category, 40)
    bounded = max(0.0, min(1.0, confidence))
    raw = int(round(weight * (0.55 + 0.45 * bounded)))
    return min(BAND_CEILING.get(band, 75), raw)


def calibrate(band: str, source_count: int) -> float:
    base = {"speculative": 0.35, "supported": 0.62, "strong": 0.84}[band]
    if source_count >= 2 and band == "strong":
        base = min(0.95, base + 0.08)
    return base


def family_key(path: str) -> str:
    parts = [part for part in (path or "").split("/") if part]
    template_at = None
    for index, part in enumerate(parts):
        if part.startswith("{") and part.endswith("}"):
            template_at = index
    if template_at is None:
        return ""
    return "/" + "/".join(parts[: template_at + 1])


def version_root(path: str) -> str:
    parts = [part for part in (path or "").split("/") if part]
    for index, part in enumerate(parts):
        if _VERSION.match(part):
            return "/" + "/".join(parts[: index + 1])
    return ""


def build_hypotheses(db, engagement_id: int) -> list[dict]:
    endpoints = db.list_endpoints(engagement_id)
    parameters = db.list_parameters(engagement_id)
    assets = db.list_assets(engagement_id)
    relationships = db.list_relationships(engagement_id)
    changes = db.list_changes(engagement_id)
    surface = db.list_surface(engagement_id, limit=1000)
    operations = db.list_events(engagement_id, kind="api_operation", limit=1000)
    drafts: list[dict] = []

    events = db.list_events(engagement_id, limit=2000)
    drafts.extend(_tenant_boundaries(endpoints, parameters, events))
    drafts.extend(_spec_boundaries(operations))
    drafts.extend(_secrets(db, engagement_id))
    drafts.extend(_client_bundles(db, engagement_id, parameters))
    drafts.extend(_historical(surface, events))
    drafts.extend(_parameters(parameters))
    drafts.extend(_graphql(endpoints))
    drafts.extend(_admin_without_spec(endpoints, operations))
    drafts.extend(_cors_and_cookies(db, engagement_id))
    drafts.extend(_changes(changes, assets))
    drafts.extend(_client_only_hosts(assets))
    drafts.extend(_trust(relationships))
    return _dedupe(drafts)[:80]


def record_version_shifts(db, engagement_id: int, job_id: int | None) -> None:
    live: dict[str, set[str]] = defaultdict(set)
    historical: dict[tuple[str, str], list[str]] = defaultdict(list)
    for row in db.list_surface(engagement_id, limit=1000):
        root = version_root(row["templated_path"])
        if not root:
            continue
        if row["last_source"] in LIVE_SOURCES or row["first_source"] in LIVE_SOURCES:
            live[row["host"]].add(root)
        if row["first_source"] in HISTORICAL_SOURCES and row["last_source"] in HISTORICAL_SOURCES:
            historical[(row["host"], root)].append(row["templated_path"])
    for (host, root), paths in historical.items():
        current = sorted(live.get(host, set()))
        if not current or root in live.get(host, set()):
            continue
        db.add_change(
            engagement_id,
            job_id,
            "functionality_shifted",
            f"{host}{root}",
            root,
            ", ".join(current),
            "change_detect",
        )


class _Lead:
    def __init__(self) -> None:
        self.drafts: list[dict] = []


def _tenant_boundaries(endpoints: list[dict], parameters: list[dict], events: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for endpoint in endpoints:
        parent = family_key(endpoint["templated_path"])
        if not parent:
            continue
        groups[(endpoint["host"], parent)].append(endpoint)
    drafts = []
    for (host, parent), members in groups.items():
        paths = sorted({item["templated_path"] for item in members})
        if len(paths) < 2:
            continue
        names = [
            row["name"]
            for row in parameters
            if row["host"] == host and row["templated_path"] in paths
        ]
        listed = [f"{item['method']} {host}{item['templated_path']}" for item in members]
        drafts.append(
            _draft(
                category="tenant_boundary",
                dedupe_key=f"{host}{parent}",
                subject=f"{host}{parent}",
                title=f"Routes under {parent} share an identifier",
                summary=(
                    f"{len(paths)} routes are nested under {parent}. "
                    "A boundary mistake on the shared identifier would affect the whole group."
                ),
                band="supported",
                source_count=len({item["sources"] for item in members}),
                assets=[host],
                endpoints=sorted(set(listed)),
                observations=_route_observations(host, members, events),
                why=(
                    f"These routes were prioritized together because they hang off {parent}, "
                    "not because each path was classified separately."
                ),
                limitations=(
                    "The grouping is structural. The case file does not show whether the service "
                    "enforces the same check on every route."
                    + (f" Parameter names in the group: {', '.join(sorted(set(names))[:8])}." if names else "")
                ),
                validation=(
                    "Review whether each route in this group applies the same authorization boundary "
                    "for the shared identifier."
                ),
            )
        )
    return drafts


def _spec_boundaries(operations: list[dict]) -> list[dict]:
    drafts = []
    for event in operations:
        meta = event.get("meta") or {}
        path = str(meta.get("path") or "")
        method = str(meta.get("method") or "GET")
        security = meta.get("security")
        names = [item.get("name", "") for item in meta.get("parameters") or [] if isinstance(item, dict)]
        classification, _functionality = classify_endpoint(path, names)
        if classification != "admin" or security != []:
            continue
        subject = f"{method} {event['subject']}{path}"
        drafts.append(
            _draft(
                category="unauthenticated_admin_spec",
                dedupe_key=subject,
                subject=subject,
                title="API spec lists an admin operation without a security scheme",
                summary=(
                    "The specification describes an administrative operation and does not declare a security scheme."
                ),
                band="strong",
                source_count=1,
                assets=[event["subject"]],
                endpoints=[subject],
                observations=[_event_ref(event)],
                why="A missing security scheme on an administrative operation is direct evidence from the specification.",
                limitations="A specification can be incomplete or stale. This does not show the live response.",
                validation="Confirm whether the deployed operation requires authorization.",
            )
        )
    return drafts


def _secrets(db, engagement_id: int) -> list[dict]:
    drafts = []
    for event in db.list_events(engagement_id, kind="credential_pattern", limit=100):
        pattern = event["value"]
        drafts.append(
            _draft(
                category="exposed_secret_pattern",
                dedupe_key=f"{pattern}:{event['subject']}",
                subject=event["subject"],
                title=f"Public response matches a {pattern} pattern",
                summary="A public response matches a credential-like pattern. The matched value was not stored.",
                band="strong",
                source_count=1,
                assets=[event["subject"]],
                endpoints=[],
                observations=[_event_ref(event)],
                why="The pattern was observed in a public response, so the lead points at a specific file rather than a guess.",
                limitations="Pattern matches include examples and placeholders. Only a person can decide if it is a real secret.",
                validation="Open the referenced public file and confirm whether the pattern is a real credential.",
            )
        )
    return drafts


def _client_bundles(db, engagement_id: int, parameters: list[dict]) -> list[dict]:
    bundles: dict[str, dict] = defaultdict(lambda: {"endpoints": [], "flags": [], "maps": [], "paths": []})
    for event in db.list_events(engagement_id, kind="js_endpoint", limit=1000):
        bundles[event.get("evidence") or event["subject"]]["endpoints"].append(event)
    for event in db.list_events(engagement_id, kind="feature_flag", limit=200):
        bundles[event.get("evidence") or event["subject"]]["flags"].append(event)
    for event in db.list_events(engagement_id, kind="sourcemap_url", limit=50):
        bundles[event.get("subject") or event["value"]]["maps"].append(event)
    map_owner = {
        event["value"]: (event.get("evidence") or event["subject"])
        for event in db.list_events(engagement_id, kind="sourcemap_url", limit=50)
    }
    for event in db.list_events(engagement_id, kind="source_path", limit=100):
        script = map_owner.get(event["subject"]) or event.get("evidence") or event["subject"]
        bundles[script]["paths"].append(event)
    drafts = []
    for script, parts in bundles.items():
        if not any(parts.values()):
            continue
        observations = [
            _event_ref(event)
            for group in parts.values()
            for event in group
        ]
        endpoint_values = sorted({event["value"] for event in parts["endpoints"]})
        flags = sorted({event["value"] for event in parts["flags"]})
        paths = sorted({event["value"] for event in parts["paths"]})[:8]
        host = ""
        if parts["endpoints"]:
            host = parts["endpoints"][0]["subject"]
        elif parts["flags"]:
            host = parts["flags"][0]["subject"]
        related_params = [
            row["name"]
            for row in parameters
            if row["source"] == "js_analysis" and row["templated_path"] in endpoint_values
        ]
        if not endpoint_values and not flags and not parts["maps"]:
            continue
        drafts.append(
            _draft(
                category="client_bundle",
                dedupe_key=script or host,
                subject=script or host,
                title="One client script exposes related behavior",
                summary=_bundle_summary(endpoint_values, flags, paths),
                band="supported" if endpoint_values or parts["maps"] else "speculative",
                source_count=1,
                assets=[host] if host else [],
                endpoints=endpoint_values,
                observations=observations,
                why="Endpoints, flags, and source paths were grouped because they came from the same script.",
                limitations=(
                    "Names extracted from a bundle are hints. "
                    + (f"Parameter names seen with these paths: {', '.join(sorted(set(related_params))[:8])}. " if related_params else "")
                    + "Source file contents were not copied into this case."
                ),
                validation="Review the referenced script and decide which of these routes and flags are actually reachable.",
            )
        )
    return drafts


def _historical(surface: list[dict], events: list[dict]) -> list[dict]:
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    live_versions: dict[str, set[str]] = defaultdict(set)
    live_paths = set()
    indexed = {
        (event.get("subject"), event.get("value")): event
        for event in events
        if event.get("kind") in {"surface_url", "historical_url"}
    }
    for row in surface:
        root = version_root(row["templated_path"])
        if root and (row["last_source"] in LIVE_SOURCES or row["first_source"] in LIVE_SOURCES):
            live_versions[row["host"]].add(root)
        if row["last_source"] in LIVE_SOURCES or row["first_source"] in LIVE_SOURCES:
            live_paths.add((row["host"], row["templated_path"]))
    for row in surface:
        if row["first_source"] not in HISTORICAL_SOURCES or row["last_source"] not in HISTORICAL_SOURCES:
            continue
        if (row["host"], row["templated_path"]) in live_paths:
            continue
        if not _interesting_history(row["templated_path"]):
            continue
        key = version_root(row["templated_path"]) or _coarse_prefix(row["templated_path"])
        groups[(row["host"], key)].append(row)
    drafts = []
    for (host, prefix), rows in list(groups.items())[:8]:
        paths = sorted({row["templated_path"] for row in rows})
        sources = sorted({row["first_source"] for row in rows})
        current = sorted(live_versions.get(host, set()) - {prefix})
        current_note = f" Current generation observed: {', '.join(current)}." if current else ""
        drafts.append(
            _draft(
                category="historical_functionality",
                dedupe_key=f"{host}{prefix}",
                subject=f"{host}{prefix}",
                title=f"Historical functionality under {prefix} was not seen in the current collection",
                summary=(
                    f"{len(paths)} historical path(s) under {prefix} are absent from the current probe and crawl."
                    + current_note
                ),
                band="supported",
                source_count=len(sources),
                assets=[host],
                endpoints=[f"{host}{path}" for path in paths[:12]],
                observations=[
                    _event_ref(indexed[(host, row["url"])])
                    if (host, row["url"]) in indexed
                    else {
                        "record": "surface_url",
                        "source": row["first_source"],
                        "kind": "historical_url",
                        "subject": host,
                        "value": row["url"],
                    }
                    for row in rows[:12]
                ],
                why="These paths were kept as one lead because they document the same historical area, not as one lead per URL.",
                limitations="A historical URL can be retired, renamed, or still deployed outside the current crawl.",
                validation="Compare this historical group with the current application and decide whether any of it is still deployed.",
            )
        )
    return drafts


def _parameters(parameters: list[dict]) -> list[dict]:
    drafts = []
    for row in parameters:
        if not is_sensitive_parameter(row["name"]):
            continue
        subject = f"{row['host']}{row['templated_path']}?{row['name']}"
        drafts.append(
            _draft(
                category="sensitive_parameter",
                dedupe_key=subject,
                subject=subject,
                title=f"Parameter {row['name']} is worth a manual look",
                summary=(
                    f"Parameter '{row['name']}' on {row['templated_path']} belongs to a name class "
                    "such as redirect, file, url, template, or callback."
                ),
                band="supported",
                source_count=1,
                assets=[row["host"]],
                endpoints=[f"{row['host']}{row['templated_path']}"],
                observations=[
                    {
                        "record": "parameter",
                        "id": row.get("id"),
                        "source": row["source"],
                        "kind": row["location"],
                        "subject": row["host"],
                        "value": row["name"],
                    }
                ],
                why="The parameter name was observed directly. The lead exists because of that name, not a guessed payload.",
                limitations="A parameter name does not show how the application uses the value. Values are not stored.",
                validation="Review how the application uses this parameter.",
            )
        )
    return drafts


def _graphql(endpoints: list[dict]) -> list[dict]:
    drafts = []
    for endpoint in endpoints:
        if endpoint["classification"] != "graphql":
            continue
        subject = f"{endpoint['method']} {endpoint['host']}{endpoint['templated_path']}"
        drafts.append(
            _draft(
                category="graphql",
                dedupe_key=subject,
                subject=subject,
                title="GraphQL endpoint observed",
                summary="A GraphQL endpoint was observed.",
                band="supported",
                source_count=1,
                assets=[endpoint["host"]],
                endpoints=[subject],
                observations=[
                    {
                        "record": "endpoint",
                        "source": endpoint["sources"],
                        "kind": "endpoint",
                        "subject": endpoint["host"],
                        "value": subject,
                    }
                ],
                why="The path was classified from an observed route.",
                limitations="The case file does not list the operations the endpoint allows.",
                validation="Review authentication and which operations are exposed.",
            )
        )
    return drafts


def _admin_without_spec(endpoints: list[dict], operations: list[dict]) -> list[dict]:
    covered = set()
    for event in operations:
        meta = event.get("meta") or {}
        if meta.get("security") == []:
            covered.add(str(meta.get("path") or ""))
    drafts = []
    for endpoint in endpoints:
        if endpoint["classification"] != "admin":
            continue
        if endpoint["templated_path"] in covered:
            continue
        subject = f"{endpoint['method']} {endpoint['host']}{endpoint['templated_path']}"
        drafts.append(
            _draft(
                category="admin_surface",
                dedupe_key=subject,
                subject=subject,
                title="Administrative path observed",
                summary="An endpoint was classified as administrative from its path.",
                band="supported",
                source_count=1,
                assets=[endpoint["host"]],
                endpoints=[subject],
                observations=[
                    {
                        "record": "endpoint",
                        "source": endpoint["sources"],
                        "kind": "endpoint",
                        "subject": endpoint["host"],
                        "value": subject,
                    }
                ],
                why="The path itself is the evidence. No specification was available to say more.",
                limitations="Path classification can be wrong. This lead does not show an authorization failure.",
                validation="Review whether the route is intended to be reachable and how authorization is enforced.",
            )
        )
    return drafts


def _cors_and_cookies(db, engagement_id: int) -> list[dict]:
    drafts = []
    for event in db.list_events(engagement_id, kind="http_snapshot", limit=300):
        acao = str((event.get("meta") or {}).get("acao") or "")
        acac = str((event.get("meta") or {}).get("acac") or "").lower()
        if acao == "*" and acac in {"true", "1"}:
            drafts.append(
                _draft(
                    category="cors_posture",
                    dedupe_key=event["subject"],
                    subject=event["subject"],
                    title="CORS allows any origin with credentials",
                    summary="A response allows any origin and also allows credentials.",
                    band="strong",
                    source_count=1,
                    assets=[event["subject"]],
                    endpoints=[event["subject"]],
                    observations=[_event_ref(event)],
                    why="Both headers were present on the same observed response.",
                    limitations="The headers might apply only to this response.",
                    validation="Review whether that header combination is intentional.",
                )
            )
    for event in db.list_events(engagement_id, kind="cookie_flag", limit=200):
        meta = event.get("meta") or {}
        name = str(meta.get("name") or event["value"]).lower()
        if meta.get("httponly") or not any(token in name for token in ("session", "sid", "auth", "token")):
            continue
        drafts.append(
            _draft(
                category="session_cookie",
                dedupe_key=f"{event['subject']}:{event['value']}",
                subject=event["subject"],
                title=f"Cookie {event['value']} has no HttpOnly flag",
                summary="A cookie whose name looks session-related was set without HttpOnly. The cookie value was not stored.",
                band="supported",
                source_count=1,
                assets=[event["subject"]],
                endpoints=[],
                observations=[_event_ref(event)],
                why="The flag was read from the response. The value was discarded.",
                limitations="The cookie name only suggests a session. It may be unrelated.",
                validation="Review the cookie flags on the referenced host.",
            )
        )
    return drafts


def _changes(changes: list[dict], assets: list[dict]) -> list[dict]:
    by_host = {row["normalized"]: row for row in assets}
    drafts = []
    for change in changes:
        if change["change_type"] == "added" and str(change["subject"]).startswith("domain:"):
            host = change["after_value"]
            sources = set((by_host.get(host, {}).get("sources") or "").split(","))
            sources.discard("")
            if not sources or sources <= {"seed"}:
                continue
            drafts.append(
                _draft(
                    category="new_asset",
                    dedupe_key=change["subject"],
                    subject=host,
                    title=f"New host {host}",
                    summary=f"Host {host} was first recorded from {', '.join(sorted(sources))}.",
                    band="speculative",
                    source_count=len(sources),
                    assets=[host],
                    endpoints=[],
                    observations=[
                        {
                            "record": "change",
                            "id": change.get("id"),
                            "source": change.get("source"),
                            "kind": "added",
                            "subject": host,
                            "value": ",".join(sorted(sources)),
                        }
                    ],
                    why="The host was not part of the original seed list.",
                    limitations="A new name is not by itself a weakness.",
                    validation="Decide whether this host belongs in a later authorized pass.",
                )
            )
        if change["change_type"] == "modified" and str(change["subject"]).startswith("technology:"):
            drafts.append(
                _draft(
                    category="tech_change",
                    dedupe_key=change["subject"],
                    subject=change["subject"],
                    title="Technology fingerprint changed",
                    summary=(
                        f"Earlier value '{change['before_value']}', later value '{change['after_value']}'."
                    ),
                    band="supported",
                    source_count=1,
                    assets=[change["subject"]],
                    endpoints=[],
                    observations=[
                        {
                            "record": "change",
                            "id": change.get("id"),
                            "source": change.get("source"),
                            "kind": "modified",
                            "subject": change["subject"],
                            "value": change["after_value"],
                        }
                    ],
                    why="The stored fingerprint changed between observations.",
                    limitations="A version string from a header can be incomplete.",
                    validation="Confirm which build is actually deployed before relying on the version.",
                )
            )
    return drafts


def _client_only_hosts(assets: list[dict]) -> list[dict]:
    drafts = []
    for asset in assets:
        sources = set((asset.get("sources") or "").split(","))
        sources.discard("")
        if "js_analysis" in sources and not sources.intersection({"dns_resolve", "http_probe", "httpx", "seed"}):
            drafts.append(
                _draft(
                    category="client_only_host",
                    dedupe_key=asset["normalized"],
                    subject=asset["normalized"],
                    title=f"{asset['normalized']} is referenced only from client code",
                    summary="This in-scope hostname has no DNS or HTTP observation yet.",
                    band="speculative",
                    source_count=1,
                    assets=[asset["normalized"]],
                    endpoints=[],
                    observations=[
                        {
                            "record": "asset",
                            "id": asset.get("id"),
                            "source": "js_analysis",
                            "kind": "js_host",
                            "subject": asset["normalized"],
                            "value": ",".join(sorted(sources)),
                        }
                    ],
                    why="The name exists only because client code mentioned it.",
                    limitations="The name may be unused, internal, or not deployed.",
                    validation="Decide whether the host belongs in a later authorized pass.",
                )
            )
    return drafts


def _trust(relationships: list[dict]) -> list[dict]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for relation in relationships:
        if relation["rel"] not in {"spf_includes", "cname", "script_src", "redirect", "csp_allows"}:
            continue
        if relation["in_scope_dst"]:
            continue
        grouped[relation["src"]].append(relation)
    drafts = []
    for src, relations in grouped.items():
        destinations = sorted({f"{item['rel']} {item['dst']}" for item in relations})
        drafts.append(
            _draft(
                category="trust_boundary",
                dedupe_key=src,
                subject=src,
                title=f"{src} depends on {len(destinations)} external name(s)",
                summary="External names were observed and were not scanned.",
                band="supported",
                source_count=len({item["source"] for item in relations}),
                assets=[src],
                endpoints=destinations,
                observations=[
                    {
                        "record": "relationship",
                        "id": item.get("id"),
                        "source": item["source"],
                        "kind": item["rel"],
                        "subject": src,
                        "value": item["dst"],
                    }
                    for item in relations
                ],
                why="The relationships were grouped by the in-scope name instead of filed as separate leads.",
                limitations="An external dependency is not a vulnerability. None of these names were requested.",
                validation="Review which of these dependencies are intended.",
            )
        )
    return drafts


def _draft(
    *,
    category: str,
    dedupe_key: str,
    subject: str,
    title: str,
    summary: str,
    band: str,
    source_count: int,
    assets: list[str],
    endpoints: list[str],
    observations: list[dict],
    why: str,
    limitations: str,
    validation: str,
) -> dict:
    confidence = calibrate(band, source_count)
    evidence = {
        "observations": observations,
        "assets": [item for item in assets if item],
        "endpoints": endpoints,
        "why_prioritized": why,
        "limitations": limitations,
        "confidence_band": band,
    }
    return {
        "dedupe_key": f"{category}:{dedupe_key}",
        "title": title,
        "category": category,
        "subject": subject,
        "summary": summary,
        "priority": priority_for(category, confidence, band),
        "confidence": confidence,
        "confidence_band": band,
        "rationale": why,
        "limitations": limitations,
        "validation_steps": validation,
        "evidence": evidence,
        "_paths": set(endpoints),
        "_assets": set(evidence["assets"]),
    }


def _dedupe(drafts: list[dict]) -> list[dict]:
    family_paths: set[str] = set()
    spec_paths: set[str] = set()
    covered_hosts: set[str] = set()
    bundle_hosts: set[str] = set()
    for draft in drafts:
        if draft["category"] == "tenant_boundary":
            family_paths.update(draft["_paths"])
        if draft["category"] == "unauthenticated_admin_spec":
            spec_paths.update(draft["_paths"])
        if draft["category"] == "client_bundle":
            bundle_hosts.update(draft["_assets"])
        if draft["category"] in {"client_bundle", "client_only_host", "tenant_boundary", "historical_functionality"}:
            covered_hosts.update(draft["_assets"])
    kept: list[dict] = []
    seen: set[str] = set()
    for draft in drafts:
        if draft["dedupe_key"] in seen:
            continue
        if draft["category"] == "admin_surface" and _covered(draft, spec_paths | family_paths):
            continue
        if draft["category"] == "new_asset" and draft["subject"] in covered_hosts:
            continue
        if draft["category"] == "client_only_host" and draft["subject"] in bundle_hosts:
            continue
        if draft["category"] == "graphql" and _covered(draft, family_paths):
            continue
        seen.add(draft["dedupe_key"])
        draft.pop("_paths", None)
        draft.pop("_assets", None)
        kept.append(draft)
    return kept


def _covered(draft: dict, paths: set[str]) -> bool:
    own = {_route_path(item) for item in (draft.get("_paths") or set())}
    other = {_route_path(item) for item in paths}
    return bool(own) and bool(other) and own <= other


def _route_path(value: str) -> str:
    text = value.split(" ", 1)[1] if " " in value else value
    slash = text.find("/")
    return text[slash:] if slash >= 0 else text


def _route_observations(host: str, members: list[dict], events: list[dict]) -> list[dict]:
    observations = []
    for item in members:
        matched = [
            _event_ref(event)
            for event in events
            if _event_matches_route(event, host, item["templated_path"])
        ]
        if matched:
            observations.extend(matched[:4])
            continue
        observations.append(
            {
                "record": "endpoint",
                "source": item["sources"],
                "kind": "endpoint",
                "subject": host,
                "value": f"{item['method']} {item['templated_path']}",
            }
        )
    return observations


def _event_matches_route(event: dict, host: str, path: str) -> bool:
    subject = str(event.get("subject") or "")
    if host not in subject and subject != host:
        return False
    meta_path = str((event.get("meta") or {}).get("path") or "")
    value = str(event.get("value") or "")
    if meta_path == path or value == path:
        return True
    if value.startswith("http://") or value.startswith("https://"):
        from urllib.parse import urlsplit

        from blindspot.normalize import template_path

        return template_path(urlsplit(value).path or "/") == path
    return False


def _event_ref(event: dict) -> dict:
    return {
        "event_id": event.get("id"),
        "source": event.get("source"),
        "kind": event.get("kind"),
        "subject": event.get("subject"),
        "value": event.get("value"),
    }


def _bundle_summary(endpoints: list[str], flags: list[str], paths: list[str]) -> str:
    parts = []
    if endpoints:
        parts.append(f"endpoints {', '.join(endpoints[:6])}")
    if flags:
        parts.append(f"feature flags {', '.join(flags[:6])}")
    if paths:
        parts.append(f"source paths {', '.join(paths[:4])}")
    return "The script exposes " + "; ".join(parts) + "." if parts else "The script was observed."


def _interesting_history(path: str) -> bool:
    lowered = path.lower()
    if re.search(r"/v\d+", lowered):
        return True
    return any(token in lowered for token in ("/api", "/admin", "/graphql", "/auth", "/internal", "/legacy", "/oauth"))


def _coarse_prefix(path: str) -> str:
    parts = [part for part in path.split("/") if part]
    if not parts:
        return "/"
    return "/" + "/".join(parts[:2])
