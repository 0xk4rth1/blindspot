"""Optional external programs. Missing binaries are skipped, not fatal."""

from __future__ import annotations

import asyncio
import json
import shutil
from typing import Awaitable, Callable

from blindspot.config import ToolToggle
from blindspot.safety import sanitize_tool_args

ToolRunner = Callable[[str, list[str], int, str | None], Awaitable[tuple[int, str, str]]]


def tool_path(toggle: ToolToggle) -> str | None:
    if not toggle.enabled:
        return None
    return shutil.which(toggle.path)


async def default_tool_runner(
    binary: str,
    args: list[str],
    timeout: int,
    stdin_text: str | None = None,
) -> tuple[int, str, str]:
    process = await asyncio.create_subprocess_exec(
        binary,
        *args,
        stdin=asyncio.subprocess.PIPE if stdin_text is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    if stdin_text is not None and process.stdin is not None:
        process.stdin.write(stdin_text.encode("utf-8"))
        process.stdin.close()
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []

    async def _drain(stream: asyncio.StreamReader | None, chunks: list[bytes]) -> None:
        if stream is None:
            return
        while True:
            block = await stream.read(65536)
            if not block:
                return
            chunks.append(block)

    try:
        await asyncio.wait_for(
            asyncio.gather(
                _drain(process.stdout, stdout_chunks),
                _drain(process.stderr, stderr_chunks),
                process.wait(),
            ),
            timeout=timeout,
        )
    except TimeoutError:
        process.kill()
        try:
            await asyncio.wait_for(process.wait(), timeout=2)
        except TimeoutError:
            pass
        notice = f"{binary} timed out after {timeout}s"
        err = b"".join(stderr_chunks).decode("utf-8", "replace").strip()
        if err:
            notice = f"{notice}\n{err}"
        return 124, b"".join(stdout_chunks).decode("utf-8", "replace"), notice
    return (
        process.returncode or 0,
        b"".join(stdout_chunks).decode("utf-8", "replace"),
        b"".join(stderr_chunks).decode("utf-8", "replace"),
    )


def extra_args(toggle: ToolToggle) -> list[str]:
    kept, _dropped = sanitize_tool_args(toggle.extra_args)
    return kept


def parse_host_lines(text: str) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        item = line.strip().strip(".")
        if not item or item.startswith("#") or " " in item:
            continue
        if item not in seen:
            seen.add(item)
            hosts.append(item)
    return hosts


def parse_dnsx(text: str) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        item = line.strip()
        if not item:
            continue
        if item.startswith("{") and item.endswith("}"):
            try:
                payload = json.loads(item)
            except json.JSONDecodeError:
                continue
            host = str(payload.get("host") or "")
            for address in payload.get("a") or []:
                rows.append((host, "A", str(address)))
            for address in payload.get("aaaa") or []:
                rows.append((host, "AAAA", str(address)))
            cname = payload.get("cname")
            if cname:
                rows.append((host, "CNAME", str(cname)))
            continue
        parts = item.split()
        if len(parts) >= 3 and parts[1].startswith("[") and parts[1].endswith("]"):
            rows.append((parts[0], parts[1].strip("[]"), parts[2]))
        else:
            rows.append((parts[0], "", ""))
    return rows


def parse_httpx(text: str) -> list[dict]:
    rows: list[dict] = []
    for line in text.splitlines():
        item = line.strip()
        if not item:
            continue
        if item.startswith("{"):
            try:
                payload = json.loads(item)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                rows.append(payload)
            continue
        rows.append({"url": item})
    return rows


def parse_url_lines(text: str, limit: int) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        item = line.strip()
        if not item.startswith("http"):
            continue
        if item in seen:
            continue
        seen.add(item)
        urls.append(item)
        if len(urls) >= limit:
            break
    return urls
