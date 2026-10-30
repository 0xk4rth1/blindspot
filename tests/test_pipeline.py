import asyncio
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from blindspot.config import load_config
from blindspot.db import Database
from blindspot.http_client import FetchResult, urllib_transport
from blindspot.normalize import normalize_host
from blindspot.orchestrator import execute

SENTINELS = (
    b"AKIAIOSFODNN7EXAMPLE",
    b"SECRET_SOURCE_CONTENT",
    b"HIDDEN_FORM_VALUE",
    b"QUERY_SECRET_VALUE",
    b"COOKIE_SECRET_VALUE",
    b"AUTH_SECRET_VALUE",
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        self.server.hits.append(parsed.path)  # type: ignore[attr-defined]
        query = dict(parse_qsl(parsed.query))
        host, port = self.server.server_address[:2]
        base = f"http://{host}:{port}"
        if parsed.path == "/":
            body = """<html><head><title>Northwind</title>
<script src="/app.js"></script>
<script src="https://cdn.example/lib.js"></script>
</head><body>
<a href="/login">Login</a>
<form action="/login" method="post">
<input name="email"><input name="redirect">
<input type="hidden" name="csrf" value="HIDDEN_FORM_VALUE">
</form>
<div id="__NEXT_DATA__"></div>
</body></html>"""
            self._bytes(
                body.encode(),
                "text/html",
                extra=[
                    ("Server", "nginx/1.25.1"),
                    ("Set-Cookie", "session=COOKIE_SECRET_VALUE; HttpOnly; Secure"),
                    ("Set-Cookie", "auth=AUTH_SECRET_VALUE"),
                    ("Content-Security-Policy", "script-src 'self' https://cdn.example"),
                ],
            )
            return
        if parsed.path == "/app.js":
            script = (
                'const featureFlags = {"newBilling": true};\n'
                'fetch("/api/users?id=" + id + "&token=QUERY_SECRET_VALUE");\n'
                'axios.get("/admin/export");\n'
                'const key = "AKIAIOSFODNN7EXAMPLE";\n'
                "//# sourceMappingURL=app.js.map\n"
            )
            self._bytes(script.encode(), "text/javascript")
            return
        if parsed.path == "/app.js.map":
            payload = {
                "version": 3,
                "sources": ["src/admin/Export.ts"],
                "sourcesContent": ["SECRET_SOURCE_CONTENT"],
            }
            self._bytes(json.dumps(payload).encode(), "application/json")
            return
        if parsed.path == "/openapi.json":
            spec = {
                "openapi": "3.0.0",
                "paths": {
                    "/admin/export": {"post": {"responses": {"200": {"description": "ok"}}}},
                    "/api/users": {
                        "get": {
                            "security": [{"bearer": []}],
                            "parameters": [{"name": "id", "in": "query"}],
                        }
                    },
                },
            }
            self._bytes(json.dumps(spec).encode(), "application/json")
            return
        if parsed.path == "/robots.txt":
            text = f"User-agent: *\nDisallow: /secret-admin\nSitemap: {base}/sitemap.xml\n"
            self._bytes(text.encode(), "text/plain")
            return
        if parsed.path == "/sitemap.xml":
            text = f"<urlset><url><loc>{base}/reports/old</loc></url></urlset>"
            self._bytes(text.encode(), "application/xml")
            return
        if parsed.path == "/.well-known/security.txt":
            self._bytes(b"Contact: mailto:security@northwind.test\nPolicy: https://northwind.test/policy\n", "text/plain")
            return
        if parsed.path == "/humans.txt":
            self._bytes(b"Built by the lab\n", "text/plain")
            return
        if parsed.path == "/dns-query":
            name = query.get("name", "")
            record_type = query.get("type", "")
            if name == "127.0.0.1" and record_type == "A":
                body = {"Status": 0, "Answer": [{"data": "127.0.0.1"}]}
            elif name == "127.0.0.1" and record_type == "TXT":
                body = {"Status": 0, "Answer": [{"data": '"v=spf1 include:_spf.google.com -all"'}]}
            else:
                body = {"Status": 0, "Answer": []}
            self._bytes(json.dumps(body).encode(), "application/dns-json")
            return
        if parsed.path == "/crtsh":
            body = [{"name_value": "127.0.0.1\nevil.test"}]
            self._bytes(json.dumps(body).encode(), "application/json")
            return
        if parsed.path == "/wayback":
            body = [
                ["original", "timestamp", "statuscode", "mimetype"],
                [f"{base}/legacy/report", "20190401000000", "200", "text/html"],
            ]
            self._bytes(json.dumps(body).encode(), "application/json")
            return
        if parsed.path == "/collinfo.json":
            body = [{"id": "CC-MAIN-TEST", "cdx-api": f"{base}/CC-MAIN-TEST-index"}]
            self._bytes(json.dumps(body).encode(), "application/json")
            return
        if parsed.path == "/CC-MAIN-TEST-index":
            line = {"url": f"{base}/archive/item", "timestamp": "20200101000000", "status": "200", "mime": "text/html"}
            self._bytes((json.dumps(line) + "\n").encode(), "application/json")
            return
        if parsed.path == "/urlscan":
            body = {
                "results": [
                    {"page": {"url": f"{base}/scanned"}, "task": {"time": "2021-01-01T00:00:00+00:00"}},
                    {"page": {"url": "https://evil.test/nope"}, "task": {"time": "2021-01-01T00:00:00+00:00"}},
                ]
            }
            self._bytes(json.dumps(body).encode(), "application/json")
            return
        self._bytes(b"missing", "text/plain", status=404)

    def _bytes(self, body: bytes, content_type: str, status: int = 200, extra: list | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in extra or []:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)


class PipelineTests(unittest.TestCase):
    def test_local_program_collects_without_storing_secrets(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.hits = []  # type: ignore[attr-defined]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address[:2]
        base = f"http://{host}:{port}"
        unexpected: list[str] = []

        def transport(url: str, method: str, headers: dict, timeout: int, max_bytes: int) -> FetchResult:
            target = normalize_host(urlsplit(url).hostname or "")
            if target not in {"127.0.0.1", "localhost"}:
                unexpected.append(url)
                return FetchResult(url=url, status=0, headers=[], body=b"", error="off-scope transport")
            return urllib_transport(url, method, headers, timeout, max_bytes)

        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                config_path = root / "blindspot.yaml"
                config_path.write_text(
                    f"""
engagement: localtest
program: "Local fixture"
authorization: "Authorized local fixture for the test suite."
network:
  enabled: true
seeds:
  - {base}/
scope:
  include:
    - {base}/
  exclude: []
limits:
  request_delay_ms: 0
  timeout_seconds: 5
  crawl_depth: 1
  crawl_pages: 6
  max_js_files: 5
  spec_fetches: 8
  max_historical: 20
tools:
  subfinder:
    enabled: false
  amass:
    enabled: false
  dnsx:
    enabled: false
  httpx:
    enabled: false
  katana:
    enabled: false
  gau:
    enabled: false
providers:
  doh: {base}/dns-query
  crtsh: {base}/crtsh
  wayback: {base}/wayback
  commoncrawl_collinfo: {base}/collinfo.json
  urlscan: {base}/urlscan
output:
  database: case.sqlite
  report_dir: reports
""",
                    encoding="utf-8",
                )
                config = load_config(config_path)
                summary = asyncio.run(execute(config, transport=transport))
                database = (root / "case.sqlite").read_bytes()
                for secret in SENTINELS:
                    self.assertNotIn(secret, database)
                self.assertNotIn("/secret-admin", server.hits)  # type: ignore[attr-defined]
                self.assertEqual(unexpected, [])
                db = Database(root / "case.sqlite")
                try:
                    hosts = [row["normalized"] for row in db.list_assets(db.ensure_engagement("localtest", "", "x"))]
                    self.assertNotIn("evil.test", hosts)
                    self.assertNotIn("cdn.example", [row["normalized"] for row in db.list_assets(1) if row["in_scope"]])
                    names = {row["name"] for row in db.list_parameters(1)}
                    self.assertIn("email", names)
                    self.assertIn("csrf", names)
                    self.assertIn("redirect", names)
                    self.assertIn("token", names)
                    paths = {row["value"] for row in db.list_events(1, kind="source_path")}
                    self.assertIn("src/admin/Export.ts", paths)
                    robots = {row["value"] for row in db.list_events(1, kind="robots_path")}
                    self.assertIn("/secret-admin", robots)
                    categories = {row["category"] for row in db.list_hypotheses(1)}
                    self.assertIn("unauthenticated_admin_spec", categories)
                    self.assertIn("exposed_secret_pattern", categories)
                    self.assertTrue(any(row["name"] == "nginx" for row in db.list_technologies(1)))
                    relations = {(row["rel"], row["dst"]) for row in db.list_relationships(1)}
                    self.assertIn(("spf_includes", "_spf.google.com"), relations)
                    self.assertGreater(summary["queued"], 0)
                finally:
                    db.close()
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
