"""HTTP probing, fingerprints, and passive historical URL indexes."""

from __future__ import annotations

import json

from blindspot.adapters.external import extra_args, parse_httpx, parse_url_lines, tool_path
from blindspot.gate import evaluate_redirect
from blindspot.normalize import host_from_url, join_origin, origin_of, with_query
from blindspot.parsekit import (
    cookie_flags,
    csp_hosts,
    fingerprint,
    interesting_headers,
    parse_html,
    parse_robots,
    parse_security_txt,
    parse_sitemap,
)
from blindspot.safety import PolicyError, is_blocked_target
from blindspot.stages.passive import wayback_time
from blindspot.stages.result import StageResult

DOCUMENTS = ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/humans.txt")
LIVE_SOURCES = {"http_probe", "httpx", "crawl", "katana"}


class HttpProbeStage:
    name = "http_probe"

    async def execute(self, ctx) -> StageResult:
        if not ctx.config.network.enabled:
            return StageResult(self.name, note="network disabled")
        binary = tool_path(ctx.config.tools.httpx)
        urls = _probe_urls(ctx)
        if binary:
            inserted = await self._httpx(ctx, binary, urls)
            note = "httpx"
        else:
            ctx.log.info("httpx not on PATH; probing with the built-in client")
            inserted = 0
            for url in urls:
                count, _links = await record_response(ctx, url, self.name)
                inserted += count
            note = "builtin"
        for origin in _seed_origins(ctx):
            for path in DOCUMENTS:
                document = join_origin(origin, path)
                if ctx.scope.allows_url(document):
                    await self._document(ctx, document)
        return StageResult(self.name, inserted=inserted, note=note)

    async def _httpx(self, ctx, binary: str, urls: list[str]) -> int:
        args = ["-silent", "-json", "-status-code", "-title", "-no-color", *extra_args(ctx.config.tools.httpx)]
        code, stdout, stderr = await ctx.tool_runner(
            binary,
            args,
            ctx.config.limits.tool_timeout_seconds,
            "\n".join(urls),
        )
        if stderr.strip():
            ctx.log.warning(stderr.strip()[:500])
        if code not in {0, 124} and not stdout.strip():
            ctx.log.warning(f"httpx exited {code}; falling back to the built-in client")
            inserted = 0
            for url in urls:
                count, _links = await record_response(ctx, url, self.name)
                inserted += count
            return inserted
        inserted = 0
        for row in parse_httpx(stdout):
            url = str(row.get("url") or "")
            if not url or not ctx.scope.allows_url(url):
                ctx.intake.dropped += 1
                continue
            status = row.get("status_code") or row.get("status")
            try:
                status_code = int(status) if status is not None else None
            except (TypeError, ValueError):
                status_code = None
            cleaned = ctx.intake.surface(url, source="httpx", confidence=0.85, status=status_code)
            if not cleaned:
                continue
            host = host_from_url(cleaned)
            title = str(row.get("title") or "")[:160]
            tech = row.get("tech") or row.get("technologies") or []
            if isinstance(tech, str):
                tech = [tech]
            ctx.intake.event(
                source="httpx",
                kind="http_snapshot",
                subject=cleaned,
                value=str(status_code or 0),
                confidence=0.85,
                evidence=title,
                meta={"title": title, "technologies": [str(item)[:80] for item in tech[:12]]},
            )
            for name in tech:
                ctx.intake.event(
                    source="httpx",
                    kind="tech_hit",
                    subject=host,
                    value=str(name)[:80],
                    confidence=0.7,
                    evidence="httpx",
                )
            inserted += 1
        return inserted

    async def _document(self, ctx, url: str) -> None:
        try:
            result = await ctx.target_http.get(url)
        except PolicyError as exc:
            ctx.log.warning(str(exc))
            return
        if result.error or result.status != 200 or not result.text.strip():
            return
        path = url.split("?", 1)[0]
        if path.endswith("/robots.txt"):
            paths, sitemaps = parse_robots(result.text)
            for item in paths:
                ctx.intake.event(
                    source=self.name,
                    kind="robots_path",
                    subject=host_from_url(url),
                    value=item,
                    confidence=0.6,
                    evidence=url,
                )
            for sitemap in sitemaps:
                if ctx.scope.allows_url(sitemap):
                    await self._document(ctx, sitemap)
            return
        if path.endswith(".xml") or "sitemap" in path:
            for loc in parse_sitemap(result.text):
                ctx.intake.surface(loc, source="sitemap", confidence=0.55, evidence=url)
            return
        if path.endswith("security.txt"):
            facts = parse_security_txt(result.text)
            for key, value in facts.items():
                ctx.intake.event(
                    source=self.name,
                    kind="security_txt",
                    subject=host_from_url(url),
                    value=f"{key}: {value}",
                    confidence=0.8,
                    evidence=url,
                )
            return
        if path.endswith("humans.txt"):
            ctx.intake.event(
                source=self.name,
                kind="humans_txt",
                subject=host_from_url(url),
                value=" ".join(result.text.split())[:200],
                confidence=0.5,
                evidence=url,
            )


class FingerprintStage:
    name = "fingerprint"

    async def execute(self, ctx) -> StageResult:
        inserted = 0
        for event in ctx.db.list_events(ctx.engagement_id, kind="tech_hit", limit=2000):
            if not event["subject"]:
                continue
            meta = event["meta"] or {}
            ctx.db.upsert_technology(
                ctx.engagement_id,
                host=event["subject"],
                name=event["value"],
                version=str(meta.get("version") or ""),
                source=event["source"],
                confidence=float(event["confidence"]),
            )
            inserted += 1
        return StageResult(self.name, inserted=inserted)


class WaybackStage:
    name = "wayback"

    async def execute(self, ctx) -> StageResult:
        return await _historical_cdx(ctx, self.name, ctx.config.providers.wayback, wayback=True)


class CommonCrawlStage:
    name = "commoncrawl"

    async def execute(self, ctx) -> StageResult:
        if not ctx.config.network.enabled:
            return StageResult(self.name, note="network disabled")
        try:
            result = await ctx.provider_http.get(
                ctx.config.providers.commoncrawl_collinfo,
                headers={"Accept": "application/json"},
            )
        except PolicyError as exc:
            ctx.log.warning(str(exc))
            return StageResult(self.name, note=str(exc))
        if result.error or result.status >= 400 or not result.text.strip():
            ctx.log.warning(f"common crawl index list unavailable: {result.status or result.error}")
            return StageResult(self.name, note="index unavailable")
        try:
            collections = json.loads(result.text)
        except json.JSONDecodeError:
            return StageResult(self.name, note="index was not JSON")
        if not isinstance(collections, list) or not collections:
            return StageResult(self.name, note="no collections")
        api = str((collections[0] or {}).get("cdx-api") or "")
        if not api:
            return StageResult(self.name, note="collection has no cdx-api")
        origin = origin_of(api).rstrip("/")
        if origin not in ctx.provider_http.allowed_origins:
            ctx.log.warning(f"common crawl cdx-api origin is not allowlisted: {origin}")
            return StageResult(self.name, note="cdx-api origin is not allowlisted")
        return await _historical_cdx(ctx, self.name, api, wayback=False)


class UrlscanStage:
    name = "urlscan"

    async def execute(self, ctx) -> StageResult:
        if not ctx.config.network.enabled:
            return StageResult(self.name, note="network disabled")
        inserted = 0
        for host in ctx.db.in_scope_hosts(ctx.engagement_id):
            url = with_query(ctx.config.providers.urlscan, {"q": f"domain:{host}", "size": "100"})
            try:
                result = await ctx.provider_http.get(url, headers={"Accept": "application/json"})
            except PolicyError as exc:
                ctx.log.warning(str(exc))
                continue
            if result.status == 401 or result.status == 429:
                ctx.log.warning(f"urlscan returned {result.status}")
                break
            if result.error or result.status >= 400 or not result.text.strip():
                continue
            try:
                payload = json.loads(result.text)
            except json.JSONDecodeError:
                continue
            for row in (payload.get("results") or [])[: ctx.config.limits.max_historical]:
                if not isinstance(row, dict):
                    continue
                page = row.get("page") or {}
                task = row.get("task") or {}
                page_url = str(page.get("url") or "")
                observed = str(task.get("time") or "") or None
                if ctx.intake.surface(
                    page_url,
                    source=self.name,
                    confidence=0.55,
                    evidence="urlscan",
                    observed_at=observed,
                ):
                    inserted += 1
        return StageResult(self.name, inserted=inserted)


class GauStage:
    name = "gau"

    async def execute(self, ctx) -> StageResult:
        if not ctx.config.network.enabled:
            return StageResult(self.name, note="network disabled")
        binary = tool_path(ctx.config.tools.gau)
        if not binary:
            return StageResult(self.name, note="gau not on PATH")
        inserted = 0
        for domain in ctx.scope.enumeration_domains():
            args = ["--subs", *extra_args(ctx.config.tools.gau), domain]
            code, stdout, stderr = await ctx.tool_runner(
                binary, args, ctx.config.limits.tool_timeout_seconds, None
            )
            if stderr.strip():
                ctx.log.warning(stderr.strip()[:400])
            if code not in {0, 124} and not stdout.strip():
                ctx.log.warning(f"gau exited {code} for {domain}")
            for url in parse_url_lines(stdout, ctx.config.limits.max_historical):
                if ctx.intake.surface(url, source=self.name, confidence=0.5, evidence="gau"):
                    inserted += 1
        return StageResult(self.name, inserted=inserted)


async def record_response(ctx, url: str, source: str) -> tuple[int, list[str]]:
    try:
        result = await ctx.target_http.get(url)
    except PolicyError as exc:
        ctx.log.warning(str(exc))
        return 0, []
    if result.error and result.status == 0:
        ctx.log.warning(f"{url} {result.error}")
        return 0, []
    cleaned = ctx.intake.surface(url, source=source, confidence=0.8, status=result.status)
    if not cleaned:
        return 0, []
    headers = result.header_map()
    location = headers.get("location", "")
    if location:
        decision, target, reason = evaluate_redirect(ctx.scope, cleaned, location)
        if decision == "allowed":
            ctx.intake.surface(target, source=source, confidence=0.6, evidence=f"redirect from {cleaned}")
        elif decision == "rejected":
            if ctx.intake.auditor is not None:
                ctx.intake.auditor.reject(target, reason)
            foreign = host_from_url(target)
            if foreign and not is_blocked_target(foreign):
                ctx.intake.external(host_from_url(cleaned), "redirect", foreign, source=source, evidence=target[:200])
    host = host_from_url(cleaned)
    header_subset = interesting_headers(headers)
    hits = fingerprint(header_subset, result.text if result.status < 400 else "")
    ctx.intake.event(
        source=source,
        kind="http_snapshot",
        subject=cleaned,
        value=str(result.status),
        confidence=0.8,
        evidence=(parse_html(result.text, cleaned).title if "html" in headers.get("content-type", "").lower() else "")[:160],
        meta={
            "headers": header_subset,
            "acao": headers.get("access-control-allow-origin", ""),
            "acac": headers.get("access-control-allow-credentials", ""),
        },
    )
    for hit in hits:
        ctx.intake.event(
            source=source,
            kind="tech_hit",
            subject=host,
            value=hit.name,
            confidence=hit.confidence,
            evidence=hit.evidence,
            meta={"version": hit.version},
        )
    for raw_cookie in result.header_values("set-cookie"):
        flags = cookie_flags(raw_cookie)
        if not flags:
            continue
        ctx.intake.event(
            source=source,
            kind="cookie_flag",
            subject=host,
            value=flags["name"],
            confidence=0.8,
            evidence=url,
            meta=flags,
        )
    policy = headers.get("content-security-policy", "")
    for allowed in csp_hosts(policy):
        ctx.intake.external(host, "csp_allows", allowed, source=source, evidence="content-security-policy")
    follow: list[str] = []
    content_type = headers.get("content-type", "").lower()
    if "html" in content_type or result.text.lstrip()[:1] == "<":
        facts = parse_html(result.text, cleaned)
        for script in facts.scripts:
            if ctx.scope.allows_url(script):
                ctx.intake.event(
                    source=source,
                    kind="script_url",
                    subject=cleaned,
                    value=script,
                    confidence=0.75,
                    evidence="script src",
                )
            else:
                foreign = host_from_url(script)
                if foreign:
                    ctx.intake.external(host, "script_src", foreign, source=source, evidence=script[:200])
        for link in facts.links:
            stored = ctx.intake.surface(link, source="link", confidence=0.45, evidence=cleaned)
            if stored:
                follow.append(stored)
        for form in facts.forms:
            action = form["action"]
            if not ctx.scope.allows_url(action):
                continue
            action_host = host_from_url(action)
            templated = _path(action)
            for name in form["inputs"]:
                ctx.intake.parameter(action_host, templated, name, "form", source)
    return 1, follow


async def _historical_cdx(ctx, source: str, api: str, wayback: bool) -> StageResult:
    if not ctx.config.network.enabled:
        return StageResult(source, note="network disabled")
    inserted = 0
    for host in ctx.db.in_scope_hosts(ctx.engagement_id):
        params = {
            "url": f"{host}/*",
            "output": "json",
            "fl": "original,timestamp,statuscode,mimetype" if wayback else "url,timestamp,status,mime",
            "limit": str(ctx.config.limits.max_historical),
        }
        if wayback:
            params["collapse"] = "urlkey"
            params["filter"] = "statuscode:200"
        try:
            result = await ctx.provider_http.get(with_query(api, params), headers={"Accept": "application/json"})
        except PolicyError as exc:
            ctx.log.warning(str(exc))
            continue
        if result.error or result.status >= 400 or not result.text.strip():
            ctx.log.warning(f"{source} unavailable for {host}: {result.status or result.error}")
            continue
        for row in _rows(result.text, wayback):
            if wayback:
                page_url = str(row.get("original") or "")
                observed = wayback_time(str(row.get("timestamp") or ""))
            else:
                page_url = str(row.get("url") or "")
                observed = wayback_time(str(row.get("timestamp") or ""))
            if ctx.intake.surface(
                page_url,
                source=source,
                confidence=0.55,
                evidence=source,
                observed_at=observed,
            ):
                inserted += 1
            if inserted >= ctx.config.limits.max_historical:
                break
    return StageResult(source, inserted=inserted)


def _rows(text: str, wayback: bool) -> list[dict]:
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return []
        if not isinstance(payload, list) or not payload:
            return []
        if wayback and payload and isinstance(payload[0], list):
            header = [str(item) for item in payload[0]]
            return [dict(zip(header, row)) for row in payload[1:] if isinstance(row, list)]
        if payload and isinstance(payload[0], dict):
            return [row for row in payload if isinstance(row, dict)]
        return []
    rows = []
    for line in stripped.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def _probe_urls(ctx) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for url in ctx.scope.seed_urls(ctx.config.seeds):
        if url not in seen:
            seen.add(url)
            urls.append(url)
    for host in ctx.db.in_scope_hosts(ctx.engagement_id):
        candidate = f"https://{host}/"
        if candidate in seen or not ctx.scope.allows_url(candidate):
            continue
        seen.add(candidate)
        urls.append(candidate)
        if len(urls) >= ctx.config.limits.max_urls:
            break
    return urls


def _seed_origins(ctx) -> list[str]:
    origins: list[str] = []
    seen: set[str] = set()
    for url in ctx.scope.seed_urls(ctx.config.seeds):
        origin = origin_of(url)
        if origin and origin not in seen:
            seen.add(origin)
            origins.append(origin)
    return origins


def _path(url: str) -> str:
    from blindspot.normalize import template_path
    from urllib.parse import urlsplit

    return template_path(urlsplit(url).path or "/")
