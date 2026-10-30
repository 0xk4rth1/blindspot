"""Normalization helpers. Query values are discarded on purpose."""

from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit, urlencode

_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)
_LONG_HEX = re.compile(r"^[0-9a-f]{16,}$", re.I)
_LONG_INT = re.compile(r"^\d{3,}$")


def normalize_host(value: str) -> str:
    host = (value or "").strip().lower().rstrip(".")
    if host.startswith("[" ) and "]" in host:
        host = host[1 : host.index("]")]
    if ":" in host and host.count(":") == 1 and not host.startswith("["):
        name, port = host.rsplit(":", 1)
        if port.isdigit():
            host = name
    return host


def host_from_url(url: str) -> str:
    parts = urlsplit(url.strip())
    return normalize_host(parts.hostname or "")


def origin_of(url: str) -> str:
    parts = urlsplit(url.strip())
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}"


def is_http_url(value: str) -> bool:
    parts = urlsplit(value.strip())
    return parts.scheme in {"http", "https"} and bool(parts.netloc)


def template_path(path: str) -> str:
    raw = path or "/"
    if not raw.startswith("/"):
        raw = "/" + raw
    segments = []
    for segment in raw.split("/"):
        if segment == "":
            segments.append(segment)
            continue
        if _UUID.match(segment):
            segments.append("{uuid}")
        elif _LONG_HEX.match(segment):
            segments.append("{hex}")
        elif _LONG_INT.match(segment):
            segments.append("{n}")
        else:
            segments.append(segment)
    templated = "/".join(segments)
    if not templated.startswith("/"):
        templated = "/" + templated
    return templated or "/"


def strip_url(url: str) -> str:
    """Return scheme://host/path with query values and fragments removed."""

    parts = urlsplit(url.strip())
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, "", ""))


def query_names(url: str) -> list[str]:
    parts = urlsplit(url.strip())
    names: list[str] = []
    seen: set[str] = set()
    for chunk in parts.query.split("&"):
        if not chunk:
            continue
        name = chunk.split("=", 1)[0].strip()
        if not name or name in seen:
            continue
        seen.add(name)
        names.append(name[:80])
    return names


def content_hash(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def join_origin(origin: str, path: str) -> str:
    base = origin.rstrip("/")
    suffix = path if path.startswith("/") else "/" + path
    return base + suffix


def with_query(base: str, params: dict[str, str]) -> str:
    parts = urlsplit(base)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update(params)
    path = parts.path or "/"
    return urlunsplit((parts.scheme, parts.netloc, path, urlencode(query), ""))
