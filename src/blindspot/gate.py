"""Fail-closed decisions for redirects, name resolution, and the request audit."""

from __future__ import annotations

from urllib.parse import urljoin

from blindspot.normalize import host_from_url
from blindspot.safety import is_blocked_target
from blindspot.scope import ScopeManager


def evaluate_redirect(scope: ScopeManager, base_url: str, location: str) -> tuple[str, str, str]:
    """Return (decision, absolute_url, reason). Decision is allowed, rejected, or ignore."""

    if not location or not location.strip():
        return "ignore", "", ""
    target = urljoin(base_url, location.strip())
    host = host_from_url(target)
    if is_blocked_target(host):
        return "rejected", target, "redirect destination is a blocked metadata address"
    if not scope.allows_url(target):
        return "rejected", target, "redirect destination is out of scope"
    return "allowed", target, ""


def alias_block_reason(scope: ScopeManager, host: str, relationships: list[dict]) -> str:
    """Refuse a request whose name now points outside the engagement."""

    normalized = host_from_url(host) if "://" in host else host.strip().lower().rstrip(".")
    for relation in relationships:
        if relation.get("src") != normalized:
            continue
        destination = str(relation.get("dst") or "")
        if relation.get("rel") == "cname" and destination and not scope.allows_host(destination):
            return f"cname target {destination} is out of scope"
        if relation.get("rel") == "resolves_to" and is_blocked_target(destination):
            return "resolved address is a blocked metadata address"
    return ""


class RequestAudit:
    """Records requests the case allowed and requests it refused."""

    def __init__(self, db, engagement_id: int, job_id: int | None):
        self.db = db
        self.engagement_id = engagement_id
        self.job_id = job_id
        self.stage = ""

    def reject(self, url: str, reason: str) -> None:
        self.db.log_request(self.engagement_id, self.job_id, self.stage, url, "rejected", reason)

    def allow(self, url: str) -> None:
        self.db.log_request(self.engagement_id, self.job_id, self.stage, url, "allowed", "")
