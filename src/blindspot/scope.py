"""Scope manager. Excludes win, and metadata addresses are never in scope."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

from blindspot.normalize import host_from_url, is_http_url, normalize_host
from blindspot.safety import PolicyError, is_blocked_target


@dataclass(frozen=True)
class ScopeRule:
    action: str
    kind: str
    pattern: str


class ScopeManager:
    def __init__(self, rules: list[ScopeRule]):
        self.rules = list(rules)

    @classmethod
    def from_lists(cls, include: list[str], exclude: list[str] | None = None) -> ScopeManager:
        rules = [parse_rule("include", item) for item in include if item and item.strip()]
        rules.extend(parse_rule("exclude", item) for item in (exclude or []) if item and item.strip())
        return cls(rules)

    @property
    def includes(self) -> list[ScopeRule]:
        return [rule for rule in self.rules if rule.action == "include"]

    @property
    def excludes(self) -> list[ScopeRule]:
        return [rule for rule in self.rules if rule.action == "exclude"]

    def allows_host(self, host: str) -> bool:
        normalized = normalize_host(host)
        if not normalized or is_blocked_target(normalized):
            return False
        if self._host_excluded(normalized):
            return False
        return self._host_included(normalized)

    def allows_url(self, url: str) -> bool:
        if not is_http_url(url):
            return False
        host = host_from_url(url)
        if not host or is_blocked_target(host):
            return False
        if self._excluded_url(url, host):
            return False
        if any(self._include_matches_url(rule, url, host) for rule in self.includes):
            return True
        return False

    def require_url(self, url: str) -> None:
        if not self.allows_url(url):
            raise PolicyError(f"out of scope: {url}")

    def enumeration_domains(self) -> list[str]:
        """Domains that passive name collectors may ask about.

        URL-prefix rules do not widen into a parent zone.
        """

        domains: list[str] = []
        seen: set[str] = set()
        for rule in self.includes:
            if rule.kind not in {"domain", "wildcard"}:
                continue
            if rule.pattern in seen:
                continue
            seen.add(rule.pattern)
            domains.append(rule.pattern)
        return domains

    def certificate_queries(self) -> list[str]:
        wildcard_bases = {rule.pattern for rule in self.includes if rule.kind == "wildcard"}
        exact = {rule.pattern for rule in self.includes if rule.kind == "domain"}
        queries: list[str] = []
        for base in sorted(wildcard_bases):
            queries.append(f"%.{base}")
        for domain in sorted(exact):
            if any(domain == base or domain.endswith("." + base) for base in wildcard_bases):
                continue
            queries.append(domain)
        for rule in self.includes:
            if rule.kind != "url_prefix":
                continue
            host = host_from_url(rule.pattern)
            if not host:
                continue
            covered = host in exact or any(
                host == base or host.endswith("." + base) for base in wildcard_bases
            )
            if not covered:
                queries.append(host)
        return queries

    def seed_urls(self, seeds: list[str]) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        for seed in seeds:
            candidate = seed.strip()
            if is_http_url(candidate):
                url = candidate if self.allows_url(candidate) else ""
            else:
                host = normalize_host(candidate)
                url = f"https://{host}/" if self.allows_url(f"https://{host}/") else ""
            if url and url not in seen:
                seen.add(url)
                urls.append(url)
        return urls

    def assert_seeds(self, seeds: list[str]) -> None:
        if not self.includes:
            raise PolicyError("scope has no include rules")
        if not seeds:
            raise PolicyError("at least one seed is required")
        for seed in seeds:
            candidate = seed.strip()
            if is_http_url(candidate):
                allowed = self.allows_url(candidate)
            else:
                allowed = self.allows_host(candidate)
            if not allowed:
                raise PolicyError(f"seed is outside scope: {seed}")

    def _host_included(self, host: str) -> bool:
        for rule in self.includes:
            if self._rule_matches_host(rule, host):
                return True
        return False

    def _host_excluded(self, host: str) -> bool:
        return any(self._rule_matches_host(rule, host) for rule in self.excludes if rule.kind != "url_prefix")

    def _excluded_url(self, url: str, host: str) -> bool:
        if self._host_excluded(host):
            return True
        return any(
            rule.kind == "url_prefix" and _prefix_match(rule.pattern, url) for rule in self.excludes
        )

    def _include_matches_url(self, rule: ScopeRule, url: str, host: str) -> bool:
        if rule.kind == "url_prefix":
            return _prefix_match(rule.pattern, url)
        return self._rule_matches_host(rule, host)

    def _rule_matches_host(self, rule: ScopeRule, host: str) -> bool:
        if rule.kind == "domain":
            return host == rule.pattern
        if rule.kind == "wildcard":
            return host == rule.pattern or host.endswith("." + rule.pattern)
        if rule.kind == "ip":
            return host == rule.pattern
        if rule.kind == "cidr":
            try:
                return ipaddress.ip_address(host) in ipaddress.ip_network(rule.pattern, strict=False)
            except ValueError:
                return False
        if rule.kind == "url_prefix":
            return host_from_url(rule.pattern) == host
        return False


def parse_rule(action: str, raw: str) -> ScopeRule:
    pattern = raw.strip()
    if is_http_url(pattern):
        return ScopeRule(action, "url_prefix", pattern)
    if "/" in pattern:
        try:
            network = ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            network = None
        if network is not None:
            return ScopeRule(action, "cidr", str(network))
    if pattern.startswith("*."):
        base = normalize_host(pattern[2:])
        if not base or "." not in base and base != "localhost":
            raise PolicyError(f"invalid wildcard scope: {raw}")
        return ScopeRule(action, "wildcard", base)
    try:
        address = ipaddress.ip_address(pattern)
    except ValueError:
        address = None
    if address is not None:
        return ScopeRule(action, "ip", str(address))
    host = normalize_host(pattern)
    if not host or " " in host or "/" in host:
        raise PolicyError(f"invalid scope rule: {raw}")
    return ScopeRule(action, "domain", host)


def _prefix_match(pattern_url: str, url: str) -> bool:
    pattern = urlsplit(pattern_url.strip())
    candidate = urlsplit(url.strip())
    if pattern.scheme and candidate.scheme and pattern.scheme.lower() != candidate.scheme.lower():
        return False
    if normalize_host(pattern.hostname or "") != normalize_host(candidate.hostname or ""):
        return False
    if _effective_port(pattern) != _effective_port(candidate):
        return False
    prefix = pattern.path or "/"
    path = candidate.path or "/"
    if prefix == "/":
        return True
    prefix = prefix.rstrip("/")
    return path == prefix or path.startswith(prefix + "/")


def _effective_port(parts) -> int | None:
    if parts.port:
        return parts.port
    scheme = (parts.scheme or "").lower()
    if scheme == "http":
        return 80
    if scheme == "https":
        return 443
    return None
