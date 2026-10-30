"""Local case viewer. Bound to loopback only."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from blindspot.config import AppConfig, load_config
from blindspot.dashboard.page import render_page
from blindspot.db import Database
from blindspot.report.export import case_payload, safe_json


class CaseServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], config: AppConfig):
        super().__init__(address, Handler)
        self.config = config


class Handler(BaseHTTPRequestHandler):
    server: CaseServer

    def log_message(self, fmt: str, *args) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        if not self._local():
            self._send(403, b"local only")
            return
        path = urlsplit(self.path).path
        if path == "/":
            body = render_page("").encode("utf-8")
            self._send(200, body, "text/html; charset=utf-8")
            return
        if path == "/api/bootstrap":
            payload = self._payload()
            self._send(200, safe_json(payload).encode("ascii"), "application/json")
            return
        self._send(404, b"not found")

    def do_POST(self) -> None:  # noqa: N802
        if not self._local():
            self._send(403, b"local only")
            return
        path = urlsplit(self.path).path
        prefix = "/api/hypotheses/"
        if not path.startswith(prefix):
            self._send(404, b"not found")
            return
        try:
            hypothesis_id = int(path[len(prefix) :])
            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(min(length, 4000))
            body = json.loads(raw.decode("utf-8") or "{}")
            status = str(body.get("status") or "")
        except (ValueError, json.JSONDecodeError):
            self._send(400, b"bad request")
            return
        db = Database(self.server.config.database_path())
        try:
            engagement_id = db.ensure_engagement(
                self.server.config.engagement,
                self.server.config.program,
                self.server.config.authorization,
            )
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
        self._send(200, json.dumps(updated).encode("utf-8"), "application/json")

    def _payload(self) -> dict:
        db = Database(self.server.config.database_path())
        try:
            engagement_id = db.ensure_engagement(
                self.server.config.engagement,
                self.server.config.program,
                self.server.config.authorization,
            )
            return case_payload(db, engagement_id)
        finally:
            db.close()

    def _local(self) -> bool:
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        return host in {"127.0.0.1", "localhost", "::1"}

    def _send(self, status: int, body: bytes, content_type: str = "text/plain; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def serve(config_path: str, port: int) -> None:
    config = load_config(config_path)
    config.validate_for_run()
    server = CaseServer(("127.0.0.1", port), config)
    print(f"Blindspot case file at http://127.0.0.1:{server.server_address[1]}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
