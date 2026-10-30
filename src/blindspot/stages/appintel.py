"""Crawling, JavaScript, source maps, and API specifications."""

from __future__ import annotations

import json
from collections import deque
from urllib.parse import urljoin, urlsplit

from blindspot.adapters.external import extra_args, parse_url_lines, tool_path
from blindspot.intake import template_path_from_url
from blindspot.normalize import host_from_url, join_origin, origin_of, strip_url, template_path
from blindspot.parsekit import (
    classify_endpoint,
    extract_js,
    looks_like_spec,
    parse_openapi,
    parse_spec_document,
    query_names,
)
from blindspot.safety import PolicyError
from blindspot.stages.result import StageResult
from blindspot.stages.web import record_response

SPEC_PATHS = (
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/v3/api-docs",
    "/v2/api-docs",
    "/.well-known/openapi.json",
)


class CrawlStage:
    name = "crawl"

    async def execute(self, ctx) -> StageResult:
        if not ctx.config.network.enabled:
            return StageResult(self.name, note="network disabled")
        binary = tool_path(ctx.config.tools.katana)
        if not binary:
            return await self._builtin(ctx)
        katana = await self._katana(ctx, binary)
        if "timed out" not in katana.note:
            return katana
        builtin = await self._builtin(ctx)
        return StageResult(
            self.name,
            inserted=katana.inserted + builtin.inserted,
            note="katana timed out; builtin crawl continued",
        )

    async def _katana(self, ctx, binary: str) -> StageResult:
        inserted = 0
        timed_out = False
        depth = str(ctx.config.limits.crawl_depth)
        for seed in ctx.scope.seed_urls(ctx.config.seeds):
            args = ["-u", seed, "-d", depth, "-silent", "-jc", *extra_args(ctx.config.tools.katana)]
            code, stdout, stderr = await ctx.tool_runner(
                binary, args, ctx.config.limits.tool_timeout_seconds, None
            )
            if code == 124:
                timed_out = True
            if stderr.strip():
                ctx.log.warning(stderr.strip()[:400])
            if code not in {0, 124} and not stdout.strip():
                ctx.log.warning(f"katana exited {code}")
            for url in parse_url_lines(stdout, ctx.config.limits.max_urls):
                cleaned = ctx.intake.surface(url, source="katana", confidence=0.7, evidence=seed)
                if not cleaned:
                    continue
                inserted += 1
                if urlsplit(cleaned).path.lower().endswith(".js"):
                    ctx.intake.event(
                        source="katana",
                        kind="script_url",
                        subject=seed,
                        value=cleaned,
                        confidence=0.7,
                        evidence="katana",
                    )
        note = "katana timed out" if timed_out else "katana"
        return StageResult(self.name, inserted=inserted, note=note)

    async def _builtin(self, ctx) -> StageResult:
        queue: deque[tuple[str, int]] = deque(
            (url, 0) for url in ctx.scope.seed_urls(ctx.config.seeds)
        )
        seen: set[str] = set()
        pages = 0
        while queue and pages < ctx.config.limits.crawl_pages:
            url, depth = queue.popleft()
            cleaned = strip_url(url)
            if cleaned in seen or depth > ctx.config.limits.crawl_depth:
                continue
            if not ctx.scope.allows_url(cleaned):
                continue
            seen.add(cleaned)
            pages += 1
            _count, follow = await record_response(ctx, cleaned, self.name)
            if depth >= ctx.config.limits.crawl_depth:
                continue
            for link in follow:
                if strip_url(link) not in seen:
                    queue.append((link, depth + 1))
        return StageResult(self.name, inserted=pages, note="builtin")


class JavaScriptStage:
    name = "js_analysis"

    async def execute(self, ctx) -> StageResult:
        if not ctx.config.network.enabled:
            return StageResult(self.name, note="network disabled")
        scripts: list[str] = []
        seen: set[str] = set()
        for event in ctx.db.list_events(ctx.engagement_id, kind="script_url", limit=500):
            url = event["value"]
            if url in seen or not ctx.scope.allows_url(url):
                continue
            seen.add(url)
            scripts.append(url)
        inserted = 0
        for url in scripts[: ctx.config.limits.max_js_files]:
            try:
                result = await ctx.target_http.get(url)
            except PolicyError as exc:
                ctx.log.warning(str(exc))
                continue
            if result.error or result.status >= 400 or not result.text:
                continue
            facts = extract_js(result.text)
            host = host_from_url(url)
            for item in facts.secrets:
                ctx.intake.event(
                    source=self.name,
                    kind="credential_pattern",
                    subject=url,
                    value=item["pattern"],
                    confidence=0.7,
                    evidence=url,
                    meta={"fingerprint": item["fingerprint"]},
                )
                inserted += 1
            resolved: list[tuple[str, str]] = []
            for endpoint in facts.endpoints:
                target = _resolve_endpoint(ctx, endpoint, url)
                if target is None:
                    foreign = host_from_url(endpoint) if endpoint.startswith("http") else ""
                    if foreign:
                        ctx.intake.external(host, "js_host", foreign, source=self.name, evidence=url)
                    continue
                endpoint_host, templated = target
                resolved.append((endpoint_host, templated))
                ctx.intake.event(
                    source=self.name,
                    kind="js_endpoint",
                    subject=endpoint_host,
                    value=templated,
                    confidence=0.6,
                    evidence=url,
                )
                ctx.intake.surface(
                    join_origin(origin_of(url) if endpoint_host == host else f"https://{endpoint_host}", templated),
                    source=self.name,
                    confidence=0.55,
                    evidence=url,
                )
                for name in query_names(endpoint):
                    ctx.intake.parameter(endpoint_host, templated, name, "query", self.name)
                inserted += 1
            if resolved:
                endpoint_host, templated = resolved[0]
                for name in facts.parameter_names:
                    ctx.intake.parameter(endpoint_host, templated, name, "query", self.name)
            for foreign in facts.hosts:
                if ctx.scope.allows_host(foreign):
                    ctx.intake.host(foreign, source=self.name, confidence=0.45, evidence=url)
                    ctx.intake.event(
                        source=self.name,
                        kind="js_host",
                        subject=host,
                        value=foreign,
                        confidence=0.45,
                        evidence=url,
                    )
                else:
                    ctx.intake.external(host, "js_host", foreign, source=self.name, evidence=url)
            for flag in facts.feature_flags:
                ctx.intake.event(
                    source=self.name,
                    kind="feature_flag",
                    subject=host,
                    value=flag,
                    confidence=0.5,
                    evidence=url,
                )
            if facts.sourcemap:
                mapped = urljoin(url, facts.sourcemap)
                ctx.intake.event(
                    source=self.name,
                    kind="sourcemap_url",
                    subject=url,
                    value=mapped,
                    confidence=0.8,
                    evidence=url,
                )
                inserted += 1
        return StageResult(self.name, inserted=inserted)


class SourceMapStage:
    name = "sourcemap"

    async def execute(self, ctx) -> StageResult:
        if not ctx.config.network.enabled:
            return StageResult(self.name, note="network disabled")
        inserted = 0
        seen: set[str] = set()
        for event in ctx.db.list_events(ctx.engagement_id, kind="sourcemap_url", limit=100):
            url = event["value"]
            if url in seen:
                continue
            seen.add(url)
            if not ctx.scope.allows_url(url):
                ctx.intake.external(
                    host_from_url(event["subject"]),
                    "sourcemap",
                    host_from_url(url) or url,
                    source=self.name,
                    evidence=url[:200],
                )
                continue
            try:
                result = await ctx.target_http.get(url)
            except PolicyError as exc:
                ctx.log.warning(str(exc))
                continue
            if result.error or result.status >= 400:
                continue
            try:
                document = json.loads(result.text)
            except json.JSONDecodeError:
                continue
            if not isinstance(document, dict):
                continue
            sources = document.get("sources") if isinstance(document.get("sources"), list) else []
            for path in sources[:100]:
                ctx.intake.event(
                    source=self.name,
                    kind="source_path",
                    subject=url,
                    value=str(path)[:300],
                    confidence=0.75,
                    evidence=url,
                )
                inserted += 1
            if document.get("sourcesContent"):
                ctx.intake.event(
                    source=self.name,
                    kind="sourcemap_content_present",
                    subject=url,
                    value="sourcesContent was present and was not stored",
                    confidence=0.8,
                    evidence=url,
                )
        return StageResult(self.name, inserted=inserted)


class OpenApiStage:
    name = "openapi"

    async def execute(self, ctx) -> StageResult:
        if not ctx.config.network.enabled:
            return StageResult(self.name, note="network disabled")
        candidates: list[str] = []
        seen: set[str] = set()
        for url in ctx.scope.seed_urls(ctx.config.seeds):
            origin = origin_of(url)
            for path in SPEC_PATHS:
                candidate = join_origin(origin, path)
                if candidate not in seen and ctx.scope.allows_url(candidate):
                    seen.add(candidate)
                    candidates.append(candidate)
        for row in ctx.db.list_surface(ctx.engagement_id, limit=300):
            lowered = row["url"].lower()
            if any(token in lowered for token in ("openapi", "swagger", "api-docs")):
                if row["url"] not in seen and ctx.scope.allows_url(row["url"]):
                    seen.add(row["url"])
                    candidates.append(row["url"])
        inserted = 0
        for url in candidates[: ctx.config.limits.spec_fetches]:
            try:
                result = await ctx.target_http.get(url)
            except PolicyError as exc:
                ctx.log.warning(str(exc))
                continue
            if result.error or result.status != 200 or not result.text.strip():
                continue
            document = parse_spec_document(result.text)
            if not document or not looks_like_spec(document):
                continue
            ctx.intake.event(
                source=self.name,
                kind="spec_url",
                subject=host_from_url(url),
                value=strip_url(url),
                confidence=0.85,
                evidence=url,
            )
            for operation in parse_openapi(document):
                templated = template_path(operation.path if operation.path.startswith("/") else "/" + operation.path)
                host = host_from_url(url)
                ctx.intake.event(
                    source=self.name,
                    kind="api_operation",
                    subject=host,
                    value=f"{operation.method} {templated}",
                    confidence=0.85,
                    evidence=url,
                    meta={
                        "method": operation.method,
                        "path": templated,
                        "operation_id": operation.operation_id,
                        "parameters": operation.parameters,
                        "security": operation.security,
                        "tags": operation.tags,
                    },
                )
                classification, functionality = classify_endpoint(
                    templated, [item["name"] for item in operation.parameters]
                )
                ctx.db.upsert_endpoint(
                    ctx.engagement_id,
                    host=host,
                    method=operation.method,
                    templated=templated,
                    classification=classification,
                    functionality=functionality,
                    source=self.name,
                )
                for parameter in operation.parameters:
                    ctx.intake.parameter(host, templated, parameter["name"], parameter["location"], self.name)
                inserted += 1
        return StageResult(self.name, inserted=inserted)


def _resolve_endpoint(ctx, endpoint: str, base_url: str) -> tuple[str, str] | None:
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        if not ctx.scope.allows_url(endpoint):
            return None
        return host_from_url(endpoint), template_path_from_url(strip_url(endpoint))
    if endpoint.startswith("/"):
        path = endpoint.split("?", 1)[0].split("#", 1)[0]
        return host_from_url(base_url), template_path(path)
    return None
