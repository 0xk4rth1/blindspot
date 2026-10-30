"""Boundaries that collectors are not allowed to cross."""

from __future__ import annotations

import hashlib
import re

import ipaddress

BLOCKED_HOSTS = frozenset(
    {
        "169.254.169.254",
        "169.254.170.2",
        "fd00:ec2::254",
        "metadata.google.internal",
        "metadata.goog",
    }
)

ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Tool flags that turn adapters into brute-force scanners are dropped.
DENIED_ARG_MARKERS = ("wordlist", "-brute", "-active", "-w")

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("github_token", re.compile(r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt_like", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b")),
)

PLACEHOLDER_AUTHORIZATIONS = frozenset({"", "todo", "changeme", "replace-me", "tbd"})


class PolicyError(ValueError):
    """Raised when a request would leave the authorized black-box boundary."""


def is_blocked_target(host: str) -> bool:
    normalized = (host or "").strip().lower().rstrip(".")
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    if normalized in BLOCKED_HOSTS:
        return True
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return str(address) in BLOCKED_HOSTS


def sanitize_tool_args(args: list[str]) -> tuple[list[str], list[str]]:
    kept: list[str] = []
    dropped: list[str] = []
    skip_next = False
    value_flags = {"-w", "--wordlist"}
    for arg in args:
        if skip_next:
            dropped.append(arg)
            skip_next = False
            continue
        lowered = arg.lower()
        if any(marker in lowered for marker in DENIED_ARG_MARKERS):
            dropped.append(arg)
            if lowered in value_flags:
                skip_next = True
            continue
        kept.append(arg)
    return kept, dropped


def secret_fingerprints(text: str) -> tuple[list[dict[str, str]], str]:
    """Return pattern metadata and text with matches removed.

    The raw match never leaves this function. Callers store the pattern name
    and a short hash so a later run can dedupe without keeping the value.
    """

    findings: list[dict[str, str]] = []
    redacted = text
    for name, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(redacted):
            raw = match.group(0)
            digest = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:12]
            findings.append({"pattern": name, "fingerprint": digest})
        redacted = pattern.sub(" ", redacted)
    # Collapse identical hits in one document.
    unique: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in findings:
        key = (item["pattern"], item["fingerprint"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique, redacted
