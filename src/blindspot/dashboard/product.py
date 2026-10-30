"""Local web application: one page to open a project, run it, and read it back."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

from blindspot.config import ConfigError, load_config
from blindspot.dashboard.page import render_page
from blindspot.db import Database
from blindspot.orchestrator import execute
from blindspot.projects import available_exports, create_project, describe, export_file, list_projects, project_dir
from blindspot.report.export import case_payload, export_case, safe_json

_RUNS: dict[str, dict] = {}
_RUN_LOCK = threading.Lock()


class AppServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], root: Path):
        super().__init__(address, AppHandler)
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)


class AppHandler(BaseHTTPRequestHandler):
    server: AppServer

    def log_message(self, fmt: str, *args) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        if not self._local():
            self._send(403, b"local only")
            return
        path = urlsplit(self.path).path
        if path == "/":
            self._send(200, _home(list_projects(self.server.root)).encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/api/projects":
            self._json(200, {"projects": list_projects(self.server.root)})
            return
        project = _match(path, "/projects/")
        if project and "/" not in project:
            try:
                project_dir(self.server.root, project)
            except ConfigError:
                self._send(404, b"not found")
                return
            self._send(200, render_page("", api=f"/api/projects/{project}").encode("utf-8"), "text/html; charset=utf-8")
            return
        parts = _api_parts(path)
        if parts is None:
            self._send(404, b"not found")
            return
        slug, rest = parts
        try:
            folder = project_dir(self.server.root, slug)
        except ConfigError:
            self._send(404, b"not found")
            return
        if rest == "bootstrap":
            self._json(200, _bootstrap(folder, slug))
            return
        if rest == "run":
            self._json(200, _status(folder, slug))
            return
        if rest.startswith("files/"):
            name = unquote(rest[len("files/") :])
            try:
                target = export_file(folder, name)
            except ConfigError:
                self._send(404, b"not found")
                return
            body = target.read_bytes()
            kind = "application/json" if target.suffix in {".json", ".jsonl"} else "text/plain; charset=utf-8"
            if target.suffix == ".html":
                kind = "text/html; charset=utf-8"
            self._send(200, body, kind)
            return
        self._send(404, b"not found")

    def do_POST(self) -> None:  # noqa: N802
        if not self._local():
            self._send(403, b"local only")
            return
        path = urlsplit(self.path).path
        try:
            body = _read_json(self)
        except ValueError:
            self._send(400, b"bad request")
            return
        if path == "/api/projects":
            try:
                created = create_project(
                    self.server.root,
                    name=str(body.get("name") or ""),
                    program=str(body.get("program") or ""),
                    authorization=str(body.get("authorization") or ""),
                    seeds=_as_list(body.get("seeds")),
                    include=_as_list(body.get("include")),
                    exclude=_as_list(body.get("exclude")),
                    network_enabled=bool(body.get("network", True)),
                )
            except ConfigError as exc:
                self._json(400, {"error": str(exc)})
                return
            self._json(201, created)
            return
        parts = _api_parts(path)
        if parts is None:
            self._send(404, b"not found")
            return
        slug, rest = parts
        try:
            folder = project_dir(self.server.root, slug)
        except ConfigError:
            self._send(404, b"not found")
            return
        if rest == "run":
            try:
                _start(self.server.root, slug)
            except ConfigError as exc:
                self._json(409, {"error": str(exc)})
                return
            self._json(202, _status(folder, slug))
            return
        if rest.startswith("hypotheses/"):
            try:
                hypothesis_id = int(rest[len("hypotheses/") :])
                status = str(body.get("status") or "")
            except ValueError:
                self._send(400, b"bad request")
                return
            config = load_config(folder / "blindspot.yaml")
            db = Database(config.database_path())
            try:
                engagement_id = db.ensure_engagement(config.engagement, config.program, config.authorization)
                try:
                    updated = db.set_hypothesis_status(engagement_id, hypothesis_id, status)
                except ValueError:
                    self._send(400, b"bad status")
                    return
            finally:
                db.close()
            if not updated:
                self._send(404, b"not found")
                return
            self._json(200, updated)
            return
        self._send(404, b"not found")

    def _local(self) -> bool:
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        return host in {"127.0.0.1", "localhost", "::1"}

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, safe_json(payload).encode("ascii"), "application/json")

    def _send(self, status: int, body: bytes, content_type: str = "text/plain; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def serve_app(root: str | Path, port: int) -> None:
    server = AppServer(("127.0.0.1", port), Path(root))
    print(f"Blindspot at http://127.0.0.1:{server.server_address[1]}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def _home(projects: list[dict]) -> str:
    cards = []
    for project in projects:
        summary = project["summary"]
        cards.append(
            "<a class=\"project\" href=\"/projects/{slug}\">"
            "<strong>{name}</strong>"
            "<span>{program}</span>"
            "<span>{assets} hosts · {endpoints} endpoints · {queued} queued</span>"
            "</a>".format(
                slug=escape(project["slug"]),
                name=escape(project["name"]),
                program=escape(project["program"] or "No program name"),
                assets=int(summary.get("assets") or 0),
                endpoints=int(summary.get("endpoints") or 0),
                queued=int(summary.get("queued") or 0),
            )
        )
    listing = "\n".join(cards) or "<p class=\"muted\">No projects yet.</p>"
    return HOME.replace("__PROJECTS__", listing)


def _bootstrap(folder: Path, slug: str) -> dict:
    config = load_config(folder / "blindspot.yaml")
    payload = _empty_payload(config)
    database = config.database_path()
    if database.is_file():
        db = Database(database, readonly=True)
        try:
            engagement_id = db.find_engagement(config.engagement)
            if engagement_id is not None:
                payload = case_payload(db, engagement_id)
        except sqlite3.OperationalError:
            payload = _empty_payload(config)
        finally:
            db.close()
    payload["project"] = {"slug": slug, "files": available_exports(folder)}
    return payload


def _empty_payload(config) -> dict:
    return {
        "engagement": {
            "id": None,
            "name": config.engagement,
            "program": config.program,
            "authorization": config.authorization,
            "created_at": "",
        },
        "summary": {},
        "assets": [],
        "endpoints": [],
        "parameters": [],
        "relationships": [],
        "technologies": [],
        "surface": [],
        "changes": [],
        "hypotheses": [],
        "jobs": [],
        "logs": [],
    }


def _status(folder: Path, slug: str) -> dict:
    with _RUN_LOCK:
        state = dict(_RUNS.get(slug) or {"state": "idle", "error": ""})
    state["files"] = available_exports(folder)
    stage, warning = job_progress(folder)
    state["stage"] = stage if state["state"] == "running" else ""
    state["warning"] = warning if state["state"] in {"running", "failed"} else ""
    return state


def job_progress(folder: Path) -> tuple[str, str]:
    """Return the open stage and the latest warning for the newest job."""

    database = folder / "case.sqlite"
    if not database.is_file():
        return "", ""
    import sqlite3

    try:
        connection = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
        try:
            rows = connection.execute(
                """
                SELECT level, message FROM job_logs
                WHERE job_id = (SELECT id FROM jobs ORDER BY id DESC LIMIT 1)
                ORDER BY id
                """
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error:
        return "", ""
    messages = [row[1] for row in rows]
    warning = ""
    for level, message in reversed(rows):
        if level in {"warning", "error"}:
            warning = explain_warning(message)
            break
    return active_stage(messages), warning


def explain_warning(message: str) -> str:
    lowered = message.lower()
    if "certificate_verify_failed" in lowered and "not yet valid" in lowered:
        return "The system clock looks wrong, so HTTPS calls to providers are failing. Correct the clock, then run again."
    return message[:300]


def active_stage(messages: list[str]) -> str:
    current = ""
    for message in messages:
        if message.startswith("stage start "):
            current = message.removeprefix("stage start ").split(" ", 1)[0]
        elif message.startswith("stage done ") or (
            message.startswith("stage ") and " failed:" in message
        ):
            current = ""
    return current


def _start(root: Path, slug: str) -> None:
    folder = project_dir(root, slug)
    with _RUN_LOCK:
        if _RUNS.get(slug, {}).get("state") == "running":
            raise ConfigError("this project is already running")
        _RUNS[slug] = {"state": "running", "error": ""}
    threading.Thread(target=_execute, args=(folder, slug), daemon=True).start()


def _execute(folder: Path, slug: str) -> None:
    try:
        config = load_config(folder / "blindspot.yaml")
        summary = asyncio.run(execute(config))
        export_case(config, config.report_dir())
        with _RUN_LOCK:
            _RUNS[slug] = {
                "state": "completed",
                "error": "",
                "job_id": summary.get("job_id"),
                "assets": summary.get("assets", 0),
                "queued": summary.get("queued", 0),
            }
    except Exception as exc:
        with _RUN_LOCK:
            _RUNS[slug] = {"state": "failed", "error": str(exc)}


def _match(path: str, prefix: str) -> str:
    if path.startswith(prefix):
        return path[len(prefix) :].strip("/")
    return ""


def _api_parts(path: str) -> tuple[str, str] | None:
    prefix = "/api/projects/"
    if not path.startswith(prefix):
        return None
    slug, _, rest = path[len(prefix) :].partition("/")
    if not slug or not rest:
        return None
    return slug, rest


def _read_json(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length") or "0")
    if length > 100_000:
        raise ValueError("body too large")
    raw = handler.rfile.read(length) if length else b"{}"
    body = json.loads(raw.decode("utf-8") or "{}")
    if not isinstance(body, dict):
        raise ValueError("expected an object")
    return body


def _as_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return value.splitlines()
    return []


HOME = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Blindspot</title>
<style>
:root { --bg: #14120f; --panel: #1e1b16; --line: #3a342c; --text: #f3efe4; --muted: #b3a894; --accent: #e08a3c; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 15px/1.45 "Segoe UI", "Helvetica Neue", sans-serif; }
header, main { padding: 16px 22px; }
header { border-bottom: 1px solid var(--line); }
.brand { font-weight: 700; letter-spacing: 0.04em; }
.brand span { color: var(--accent); }
.muted { color: var(--muted); }
main { display: grid; grid-template-columns: minmax(280px, 420px) 1fr; gap: 22px; }
form, .project { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 14px; }
label { display: block; margin: 10px 0 4px; color: var(--muted); }
input, textarea { width: 100%; font: inherit; color: var(--text); background: var(--bg); border: 1px solid var(--line); border-radius: 6px; padding: 8px 10px; }
textarea { min-height: 72px; }
button { margin-top: 14px; font: inherit; color: var(--text); background: var(--panel); border: 1px solid var(--accent); border-radius: 6px; padding: 8px 12px; cursor: pointer; }
.projects { display: grid; gap: 10px; align-content: start; }
a.project { display: grid; gap: 4px; color: inherit; text-decoration: none; }
a.project strong { color: var(--accent); }
.check { display: flex; gap: 8px; align-items: center; margin-top: 12px; }
.check input { width: auto; }
.error { color: #d46a5c; }
@media (max-width: 800px) { main { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<header>
  <div class="brand">Blind<span>spot</span></div>
  <p class="muted">Open a project, collect only what its scope allows, and come back to the same results.</p>
</header>
<main>
  <form id="create">
    <strong>New project</strong>
    <label for="name">Project name</label>
    <input id="name" name="name" required>
    <label for="program">Program</label>
    <input id="program" name="program" required>
    <label for="authorization">Authorization</label>
    <textarea id="authorization" name="authorization" required placeholder="The statement that this target is in scope for you"></textarea>
    <label for="seeds">Seed URLs or hosts, one per line</label>
    <textarea id="seeds" name="seeds" required placeholder="https://app.example.com"></textarea>
    <label for="include">In scope, one per line</label>
    <textarea id="include" name="include" required placeholder="*.example.com"></textarea>
    <label for="exclude">Out of scope, one per line</label>
    <textarea id="exclude" name="exclude" placeholder="payments.example.com"></textarea>
    <label class="check"><input id="network" type="checkbox" checked> Send requests to in-scope hosts</label>
    <p class="muted">Includes are combined. An exclude always wins. A wildcard includes the apex and its subdomains.</p>
    <button type="submit">Create project</button>
    <p id="error" class="error"></p>
  </form>
  <section class="projects">
    __PROJECTS__
  </section>
</main>
<script>
function lines(id) {
  return document.getElementById(id).value.split(/\\n/).map((item) => item.trim()).filter(Boolean);
}
document.getElementById("create").addEventListener("submit", async (event) => {
  event.preventDefault();
  const error = document.getElementById("error");
  error.textContent = "";
  const response = await fetch("/api/projects", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({
      name: document.getElementById("name").value,
      program: document.getElementById("program").value,
      authorization: document.getElementById("authorization").value,
      seeds: lines("seeds"),
      include: lines("include"),
      exclude: lines("exclude"),
      network: document.getElementById("network").checked
    })
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    error.textContent = body.error || "Could not create the project";
    return;
  }
  window.location.href = "/projects/" + body.slug;
});
</script>
</body>
</html>
"""
