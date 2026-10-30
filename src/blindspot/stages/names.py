"""Passive name collectors that shell out to Subfinder or Amass when installed."""

from __future__ import annotations

from blindspot.adapters.external import extra_args, parse_host_lines, tool_path
from blindspot.stages.result import StageResult


class SubfinderStage:
    name = "subfinder"

    async def execute(self, ctx) -> StageResult:
        return await _enum(ctx, self.name, ctx.config.tools.subfinder, _subfinder_args)


class AmassStage:
    name = "amass"

    async def execute(self, ctx) -> StageResult:
        return await _enum(ctx, self.name, ctx.config.tools.amass, _amass_args)


async def _enum(ctx, source: str, toggle, build_args) -> StageResult:
    if not ctx.config.network.enabled:
        return StageResult(source, note="network disabled")
    binary = tool_path(toggle)
    if not toggle.enabled:
        return StageResult(source, note="disabled")
    if not binary:
        return StageResult(source, note=f"{toggle.path or source} not on PATH")
    inserted = 0
    for domain in ctx.scope.enumeration_domains():
        args = build_args(domain, toggle)
        code, stdout, stderr = await ctx.tool_runner(
            binary,
            args,
            ctx.config.limits.tool_timeout_seconds,
            None,
        )
        if stderr.strip():
            ctx.log.warning(stderr.strip()[:400])
        if code not in {0, 124} and not stdout.strip():
            ctx.log.warning(f"{source} exited {code} for {domain}")
        for host in parse_host_lines(stdout):
            if ctx.intake.host(host, source=source, confidence=0.65, evidence=domain):
                inserted += 1
    return StageResult(source, inserted=inserted)


def _subfinder_args(domain: str, toggle) -> list[str]:
    return ["-d", domain, "-silent", *extra_args(toggle)]


def _amass_args(domain: str, toggle) -> list[str]:
    # Passive mode only. Brute and wordlist flags are removed in extra_args.
    return ["enum", "-passive", "-d", domain, *extra_args(toggle)]
