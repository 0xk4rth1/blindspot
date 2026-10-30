"""HTTP clients for in-scope targets and allowlisted provider APIs."""

from __future__ import annotations

import asyncio
import gzip
import time
import urllib.request
from dataclasses import dataclass
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener

from blindspot.normalize import host_from_url, normalize_host, origin_of
from blindspot.safety import ALLOWED_METHODS, PolicyError, is_blocked_target
from blindspot.scope import ScopeManager

USER_AGENT = "Blindspot/0.1 (authorized scope-limited recon)"

Transport = Callable[..., "FetchResult"]


@dataclass
class FetchResult:
    url: str
    status: int
    headers: list[tuple[str, str]]
    body: bytes
    error: str = ""
    truncated: bool = False

    def header_values(self, name: str) -> list[str]:
        lowered = name.lower()
        return [value for key, value in self.headers if key.lower() == lowered]

    def header(self, name: str) -> str:
        values = self.header_values(name)
        return values[0] if values else ""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def header_map(self) -> dict[str, str]:
        mapped: dict[str, str] = {}
        for key, value in self.headers:
            mapped[key.lower()] = value
        return mapped


def urllib_transport(
    url: str,
    method: str,
    headers: dict[str, str],
    timeout: int,
    max_bytes: int,
) -> FetchResult:
    request_headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "gzip", **headers}
    request = Request(url, headers=request_headers, method=method)
    opener = build_opener(_NoRedirect)
    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as exc:
        response = exc
    except URLError as exc:
        return FetchResult(url=url, status=0, headers=[], body=b"", error=str(exc.reason))
    except OSError as exc:
        return FetchResult(url=url, status=0, headers=[], body=b"", error=str(exc))
    try:
        status = getattr(response, "status", None) or response.getcode()
        header_pairs = list(response.headers.items())
        raw = response.read(max_bytes + 1)
    finally:
        response.close()
    truncated = len(raw) > max_bytes
    raw = raw[:max_bytes]
    encoding = ""
    for key, value in header_pairs:
        if key.lower() == "content-encoding":
            encoding = value.lower()
    if "gzip" in encoding:
        try:
            raw = gzip.decompress(raw)
        except (OSError, EOFError):
            pass
        raw = raw[:max_bytes]
    return FetchResult(
        url=url,
        status=int(status or 0),
        headers=header_pairs,
        body=raw,
        truncated=truncated,
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Return the 3xx response so callers can decide whether the next hop is in scope."""

    def http_error_302(self, req, fp, code, msg, headers):  # noqa: ANN001, ARG002
        return fp

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


class _Pacer:
    def __init__(self, delay_ms: int):
        self.delay = max(0, delay_ms) / 1000
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def wait(self) -> None:
        if self.delay <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            pause = self._next - now
            self._next = max(self._next, now) + self.delay
        if pause > 0:
            await asyncio.sleep(pause)


class TargetHttp:
    """Fetches only URLs the scope manager allows. Never follows an off-scope redirect."""

    def __init__(
        self,
        scope: ScopeManager,
        *,
        timeout: int,
        delay_ms: int,
        max_bytes: int,
        network_enabled: bool,
        transport: Transport | None = None,
    ):
        self.scope = scope
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.network_enabled = network_enabled
        self.transport = transport or urllib_transport
        self._pacer = _Pacer(delay_ms)

    async def request(self, url: str, *, method: str = "GET", headers: dict[str, str] | None = None) -> FetchResult:
        verb = method.upper()
        if verb not in ALLOWED_METHODS:
            raise PolicyError(f"method not permitted: {verb}")
        host = host_from_url(url)
        if is_blocked_target(host):
            raise PolicyError(f"blocked metadata address: {host}")
        if not self.scope.allows_url(url):
            raise PolicyError(f"out of scope: {url}")
        if not self.network_enabled:
            raise PolicyError("network is disabled for this case")
        await self._pacer.wait()
        return await asyncio.to_thread(
            self.transport,
            url,
            verb,
            headers or {},
            self.timeout,
            self.max_bytes,
        )

    async def get(self, url: str, *, headers: dict[str, str] | None = None) -> FetchResult:
        return await self.request(url, method="GET", headers=headers)


class ProviderHttp:
    """Fetches threat-intel APIs. Origins must be the ones named in the config."""

    def __init__(
        self,
        allowed_origins: set[str],
        *,
        timeout: int,
        delay_ms: int,
        max_bytes: int,
        network_enabled: bool,
        transport: Transport | None = None,
    ):
        self.allowed_origins = {origin.rstrip("/") for origin in allowed_origins if origin}
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.network_enabled = network_enabled
        self.transport = transport or urllib_transport
        self._pacer = _Pacer(delay_ms)

    async def get(self, url: str, *, headers: dict[str, str] | None = None) -> FetchResult:
        parts = urlsplit(url)
        host = normalize_host(parts.hostname or "")
        if parts.scheme not in {"http", "https"}:
            raise PolicyError("provider URL must be http or https")
        if is_blocked_target(host):
            raise PolicyError(f"blocked metadata address: {host}")
        if parts.scheme == "http" and host not in {"127.0.0.1", "localhost", "::1"}:
            raise PolicyError("plain HTTP providers are only allowed on loopback")
        origin = origin_of(url).rstrip("/")
        if origin not in self.allowed_origins:
            raise PolicyError(f"provider origin is not allowlisted: {origin}")
        if not self.network_enabled:
            raise PolicyError("network is disabled for this case")
        await self._pacer.wait()
        return await asyncio.to_thread(
            self.transport,
            url,
            "GET",
            headers or {},
            self.timeout,
            self.max_bytes,
        )


def provider_origins(*urls: str) -> set[str]:
    origins: set[str] = set()
    for url in urls:
        origin = origin_of(url)
        if origin:
            origins.add(origin.rstrip("/"))
    return origins
