"""Single write path for discoveries. Out-of-scope values are dropped here."""

from __future__ import annotations

from blindspot.db import Database
from blindspot.normalize import host_from_url, is_http_url, normalize_host, query_names, strip_url, template_path
from blindspot.scope import ScopeManager


class Intake:
    def __init__(self, db: Database, scope: ScopeManager, engagement_id: int, job_id: int, max_urls: int):
        self.db = db
        self.scope = scope
        self.engagement_id = engagement_id
        self.job_id = job_id
        self.max_urls = max_urls
        self.url_count = 0
        self.dropped = 0
        self.stored = 0
        self._seen_urls: set[str] = set()

    def host(
        self,
        value: str,
        *,
        source: str,
        confidence: float,
        evidence: str = "",
        observed_at: str | None = None,
    ) -> int | None:
        host = normalize_host(value)
        if not host or not self.scope.allows_host(host):
            if host:
                self.dropped += 1
            return None
        asset_type = "ip" if _is_ip(host) else "domain"
        asset_id = self.db.upsert_asset(
            self.engagement_id,
            asset_type,
            host,
            in_scope=True,
            source=source,
            confidence=confidence,
            job_id=self.job_id,
            evidence=evidence,
            observed_at=observed_at,
        )
        self.stored += 1
        return asset_id

    def external(self, src: str, rel: str, dst: str, *, source: str, evidence: str = "") -> None:
        destination = dst.strip().rstrip(".")
        if not src or not destination:
            return
        host = normalize_host(destination)
        in_scope = bool(host) and self.scope.allows_host(host)
        if host and not in_scope:
            self.db.upsert_asset(
                self.engagement_id,
                "external_name",
                host,
                in_scope=False,
                source=source,
                confidence=0.5,
                job_id=self.job_id,
                evidence=evidence,
            )
        self.db.upsert_relationship(
            self.engagement_id,
            src=src,
            rel=rel,
            dst=host or destination,
            source=source,
            evidence=evidence,
            in_scope_dst=in_scope,
        )
        self.stored += 1

    def surface(
        self,
        url: str,
        *,
        source: str,
        confidence: float,
        status: int | None = None,
        evidence: str = "",
        observed_at: str | None = None,
    ) -> str:
        if not is_http_url(url) or not self.scope.allows_url(url):
            self.dropped += 1
            return ""
        cleaned = strip_url(url)
        if cleaned not in self._seen_urls and len(self._seen_urls) >= self.max_urls:
            self.dropped += 1
            return ""
        self._seen_urls.add(cleaned)
        self.url_count = len(self._seen_urls)
        self.db.upsert_surface(
            self.engagement_id,
            cleaned,
            source=source,
            status=status,
            observed_at=observed_at,
        )
        host = host_from_url(cleaned)
        self.host(host, source=source, confidence=confidence, evidence=evidence, observed_at=observed_at)
        for name in query_names(url):
            self.parameter(host, template_path_from_url(cleaned), name, "query", source)
        self.event(
            source=source,
            kind="surface_url",
            subject=host,
            value=cleaned,
            confidence=confidence,
            evidence=evidence,
            meta={"status": status} if status is not None else {},
            observed_at=observed_at,
            trust_subject=True,
        )
        self.stored += 1
        return cleaned

    def parameter(self, host: str, templated: str, name: str, location: str, source: str) -> None:
        clean = name.strip()[:80]
        if not clean or clean.startswith("__"):
            return
        if not self.scope.allows_host(host):
            self.dropped += 1
            return
        self.db.upsert_parameter(
            self.engagement_id,
            host=host,
            templated=templated or "/",
            name=clean,
            location=location[:20],
            source=source,
        )

    def event(
        self,
        *,
        source: str,
        kind: str,
        subject: str,
        value: str,
        confidence: float,
        evidence: str = "",
        meta: dict | None = None,
        observed_at: str | None = None,
        trust_subject: bool = False,
    ) -> bool:
        if not trust_subject and not self._subject_allowed(subject):
            self.dropped += 1
            return False
        if kind in {"historical_url", "js_endpoint", "crawl_url", "script_url", "spec_url"} and is_http_url(value):
            if not self.scope.allows_url(value):
                self.dropped += 1
                return False
        inserted = self.db.add_event(
            self.engagement_id,
            source=source,
            kind=kind,
            subject=subject,
            value=value,
            confidence=confidence,
            job_id=self.job_id,
            evidence=evidence,
            meta=meta,
            observed_at=observed_at,
        )
        if inserted:
            self.stored += 1
        return inserted

    def _subject_allowed(self, subject: str) -> bool:
        if not subject:
            return True
        if is_http_url(subject):
            return self.scope.allows_url(subject)
        host = normalize_host(subject)
        if host and ("." in host or _is_ip(host)):
            return self.scope.allows_host(host)
        return True


def template_path_from_url(url: str) -> str:
    from urllib.parse import urlsplit

    return template_path(urlsplit(url).path or "/")


def _is_ip(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True
