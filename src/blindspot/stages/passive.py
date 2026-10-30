"""Certificate transparency and DNS relationship collection."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from blindspot.adapters.external import extra_args, parse_dnsx, tool_path
from blindspot.normalize import with_query
from blindspot.safety import PolicyError
from blindspot.stages.result import StageResult

_CAA = re.compile(r'issue(?:wild)?\s+"?([A-Za-z0-9.-]+)', re.I)


class CertificateTransparencyStage:
    name = "ct_logs"

    async def execute(self, ctx) -> StageResult:
        if not ctx.config.network.enabled:
            return StageResult(self.name, note="network disabled")
        queries = ctx.scope.certificate_queries()
        if not queries:
            return StageResult(self.name, note="no certificate queries for this scope")
        inserted = 0
        for query in queries:
            url = with_query(ctx.config.providers.crtsh, {"q": query, "output": "json"})
            try:
                result = await ctx.provider_http.get(url, headers={"Accept": "application/json"})
            except PolicyError as exc:
                ctx.log.warning(str(exc))
                continue
            if result.error or result.status >= 400 or not result.text.strip():
                ctx.log.warning(f"ct logs unavailable for {query}: {result.status or result.error}")
                continue
            try:
                rows = json.loads(result.text)
            except json.JSONDecodeError:
                ctx.log.warning(f"ct logs returned non-JSON for {query}")
                continue
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                for raw_name in str(row.get("name_value") or "").splitlines():
                    name = raw_name.strip().lower().rstrip(".")
                    if not name or "@" in name:
                        continue
                    if name.startswith("*."):
                        base = name[2:]
                        if ctx.scope.allows_host(base):
                            if ctx.intake.event(
                                source=self.name,
                                kind="ct_wildcard",
                                subject=base,
                                value=name,
                                confidence=0.7,
                                evidence="certificate transparency",
                            ):
                                inserted += 1
                        else:
                            ctx.intake.dropped += 1
                        continue
                    if ctx.intake.host(name, source=self.name, confidence=0.7, evidence="certificate transparency"):
                        inserted += 1
        return StageResult(self.name, inserted=inserted)


class DnsStage:
    name = "dns_resolve"

    async def execute(self, ctx) -> StageResult:
        if not ctx.config.network.enabled:
            return StageResult(self.name, note="network disabled")
        hosts = ctx.db.in_scope_hosts(ctx.engagement_id)
        binary = tool_path(ctx.config.tools.dnsx)
        inserted = 0
        if binary:
            inserted += await self._dnsx(ctx, binary, hosts)
            for host in hosts:
                inserted += await self._doh_host(ctx, host, ("MX", "NS", "CAA"))
        else:
            ctx.log.info("dnsx not on PATH; using DNS-over-HTTPS")
            for host in hosts:
                inserted += await self._doh_host(ctx, host, ("A", "AAAA", "CNAME", "MX", "NS", "CAA"))
        seen: set[str] = set()
        for host in hosts:
            inserted += await self._txt(ctx, host, seen, depth=0, follow=True)
        return StageResult(self.name, inserted=inserted, note="" if binary else "doh fallback")

    async def _dnsx(self, ctx, binary: str, hosts: list[str]) -> int:
        if not hosts:
            return 0
        args = ["-a", "-aaaa", "-cname", "-resp", "-silent", *extra_args(ctx.config.tools.dnsx)]
        code, stdout, stderr = await ctx.tool_runner(
            binary,
            args,
            ctx.config.limits.tool_timeout_seconds,
            "\n".join(hosts),
        )
        if stderr.strip():
            ctx.log.warning(stderr.strip()[:500])
        if code not in {0, 124} and not stdout.strip():
            ctx.log.warning(f"dnsx exited {code}")
        inserted = 0
        for host, record_type, value in parse_dnsx(stdout):
            if not ctx.scope.allows_host(host):
                ctx.intake.dropped += 1
                continue
            if record_type in {"A", "AAAA"} and value:
                ctx.intake.external(host, "resolves_to", value, source=self.name)
                inserted += 1
            elif record_type == "CNAME" and value:
                ctx.intake.external(host, "cname", value, source=self.name)
                inserted += 1
        return inserted

    async def _doh_host(self, ctx, host: str, types: tuple[str, ...]) -> int:
        inserted = 0
        if "A" in types:
            for value in await _answers(ctx, host, "A"):
                ctx.intake.external(host, "resolves_to", value.rstrip("."), source=self.name)
                inserted += 1
        if "AAAA" in types:
            for value in await _answers(ctx, host, "AAAA"):
                ctx.intake.external(host, "resolves_to", value.rstrip("."), source=self.name)
                inserted += 1
        if "CNAME" in types:
            for value in await _answers(ctx, host, "CNAME"):
                ctx.intake.external(host, "cname", value.rstrip("."), source=self.name)
                inserted += 1
        if "MX" in types:
            for value in await _answers(ctx, host, "MX"):
                parts = value.split()
                mail = parts[-1].rstrip(".") if parts else ""
                if mail:
                    ctx.intake.external(host, "mx", mail, source=self.name)
                    inserted += 1
        if "NS" in types:
            for value in await _answers(ctx, host, "NS"):
                ctx.intake.external(host, "ns", value.rstrip("."), source=self.name)
                inserted += 1
        if "CAA" in types:
            for value in await _answers(ctx, host, "CAA"):
                match = _CAA.search(value)
                if match:
                    ctx.intake.event(
                        source=self.name,
                        kind="caa",
                        subject=host,
                        value=match.group(1).lower(),
                        confidence=0.8,
                        evidence="CAA",
                    )
                    inserted += 1
        return inserted

    async def _txt(self, ctx, domain: str, seen: set[str], depth: int, follow: bool) -> int:
        key = domain.lower().rstrip(".")
        if not key or key in seen or depth > 3 or len(seen) > 25:
            return 0
        seen.add(key)
        inserted = 0
        from blindspot.parsekit import dmarc_policy, parse_spf, verification_service

        for record in await _answers(ctx, key, "TXT"):
            lowered = record.lower()
            if lowered.startswith("v=spf1") and follow and ctx.scope.allows_host(key):
                parsed = parse_spf(record)
                for name in parsed["includes"]:
                    ctx.intake.external(key, "spf_includes", name, source=self.name, evidence="SPF include")
                    inserted += 1
                    inserted += await self._txt(ctx, name, seen, depth + 1, follow=False)
                for name in parsed["redirects"]:
                    ctx.intake.external(key, "spf_redirect", name, source=self.name)
                    inserted += 1
            elif policy := dmarc_policy(record):
                if ctx.scope.allows_host(key):
                    ctx.intake.event(
                        source=self.name,
                        kind="dmarc_policy",
                        subject=key,
                        value=policy,
                        confidence=0.8,
                        evidence="DMARC",
                    )
                    inserted += 1
            elif service := verification_service(record):
                if ctx.scope.allows_host(key):
                    ctx.intake.event(
                        source=self.name,
                        kind="saas_verification",
                        subject=key,
                        value=service,
                        confidence=0.75,
                        evidence="DNS TXT service name only",
                    )
                    inserted += 1
        return inserted


async def _answers(ctx, name: str, record_type: str) -> list[str]:
    from blindspot.parsekit import unquote_txt

    url = with_query(ctx.config.providers.doh, {"name": name, "type": record_type})
    try:
        result = await ctx.provider_http.get(url, headers={"Accept": "application/dns-json"})
    except PolicyError as exc:
        ctx.log.warning(str(exc))
        return []
    if result.error or result.status >= 400 or not result.text.strip():
        return []
    try:
        payload = json.loads(result.text)
    except json.JSONDecodeError:
        return []
    values: list[str] = []
    for answer in payload.get("Answer") or []:
        if not isinstance(answer, dict):
            continue
        data = unquote_txt(str(answer.get("data") or ""))
        if data:
            values.append(data)
    return values


def wayback_time(value: str) -> str | None:
    raw = (value or "").strip()
    if len(raw) < 8 or not raw[:8].isdigit():
        return None
    stamp = raw[:14] if len(raw) >= 14 else raw[:8] + "000000"
    try:
        parsed = datetime.strptime(stamp, "%Y%m%d%H%M%S")
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc).isoformat()
