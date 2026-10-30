import asyncio
import json
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

from blindspot.adapters.external import default_tool_runner
from blindspot.config import ConfigError
from blindspot.dashboard.page import render_page
from blindspot.dashboard.product import AppServer, active_stage, discovery_steps, explain_warning
from blindspot.db import Database
from blindspot.orchestrator import host_discovery_stages
from blindspot.projects import create_project
from blindspot.stages.web import hosts_without_response


class ProjectTests(unittest.TestCase):
    def test_active_stage_follows_the_latest_open_stage(self) -> None:
        messages = [
            "stage start subfinder",
            "stage done subfinder inserted=0 skipped=0",
            "stage start dns_resolve",
        ]
        self.assertEqual(active_stage(messages), "dns_resolve")
        messages.append("stage dns_resolve failed: timeout")
        self.assertEqual(active_stage(messages), "")

    def test_clock_warning_is_plain_language(self) -> None:
        raw = "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate is not yet valid"
        text = explain_warning(raw)
        self.assertIn("system clock", text)
        self.assertNotIn("CERTIFICATE_VERIFY_FAILED", text)

    def test_timed_out_tool_keeps_what_it_printed(self) -> None:
        code, stdout, stderr = asyncio.run(
            default_tool_runner(
                sys.executable,
                ["-c", "print('kept.host', flush=True)\nimport time\ntime.sleep(30)"],
                1,
                None,
            )
        )
        self.assertEqual(code, 124)
        self.assertIn("kept.host", stdout)
        self.assertIn("timed out", stderr)

    def test_the_project_run_is_host_discovery(self) -> None:
        self.assertEqual(
            host_discovery_stages(),
            ["subfinder", "amass", "ct_logs", "dns_resolve", "http_probe"],
        )
        page = render_page("", api="/api/projects/nasa")
        self.assertIn("Discover hosts", page)
        self.assertIn('id="steps"', page)
        self.assertNotIn("wayback", host_discovery_stages())
        steps = discovery_steps(
            [
                "stage start subfinder",
                "stage done subfinder inserted=3",
                "stage start ct_logs",
            ]
        )
        by_name = {step["name"]: step["status"] for step in steps}
        self.assertEqual(by_name["subfinder"], "done")
        self.assertEqual(by_name["amass"], "pending")
        self.assertEqual(by_name["ct_logs"], "running")
        self.assertEqual(by_name["dns_resolve"], "pending")
        self.assertEqual(by_name["http_probe"], "pending")
        self.assertEqual([step["label"] for step in steps], ["Subfinder", "Amass", "Certificates", "DNS", "HTTP probe"])

    def test_hosts_that_do_not_answer_leave_the_working_list(self) -> None:
        self.assertEqual(
            hosts_without_response(
                ["https://live.northwind.test/", "https://dead.northwind.test/"],
                {"live.northwind.test"},
            ),
            ["dead.northwind.test"],
        )
        with TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "case.sqlite")
            try:
                engagement = db.ensure_engagement("Northwind", "program", "Authorized fictional engagement")
                for name in ("live.northwind.test", "dead.northwind.test"):
                    db.upsert_asset(
                        engagement,
                        "host",
                        name,
                        in_scope=True,
                        source="subfinder",
                        confidence=0.6,
                        job_id=None,
                    )
                retired = db.mark_hosts_inactive(engagement, ["dead.northwind.test"])
                self.assertEqual(retired, 1)
                self.assertEqual(db.in_scope_hosts(engagement), ["dead.northwind.test", "live.northwind.test"])
                self.assertEqual(db.live_hosts(engagement), ["live.northwind.test"])
                summary = db.summary(engagement)
                self.assertEqual(summary["live_hosts"], 1)
                self.assertEqual(summary["inactive_hosts"], 1)
            finally:
                db.close()

    def test_a_read_during_a_write_does_not_lock_the_case(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "case.sqlite"
            writer = Database(path)
            writer.ensure_engagement("Northwind", "program", "Authorized fictional engagement")
            writer._conn.execute("BEGIN IMMEDIATE")
            reader = Database(path, readonly=True)
            try:
                self.assertEqual(reader.find_engagement("Northwind"), 1)
                self.assertEqual(reader.summary(1)["assets"], 0)
            finally:
                reader.close()
                writer._conn.rollback()
                writer.close()
    def test_blank_authorization_and_out_of_scope_seed_are_refused(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ConfigError):
                create_project(
                    root,
                    name="Acme",
                    program="Acme",
                    authorization="",
                    seeds=["https://app.acme.test"],
                    include=["*.acme.test"],
                    exclude=[],
                )
            with self.assertRaises(ConfigError):
                create_project(
                    root,
                    name="Acme",
                    program="Acme",
                    authorization="Authorized for the Acme program",
                    seeds=["https://evil.test"],
                    include=["*.acme.test"],
                    exclude=[],
                )
            self.assertEqual(list(root.iterdir()), [])

    def test_app_saves_json_and_text_for_the_project(self) -> None:
        with TemporaryDirectory() as tmp:
            server = AppServer(("127.0.0.1", 0), Path(tmp))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_address[1]
            base = f"http://127.0.0.1:{port}"
            try:
                home = urllib.request.urlopen(base + "/").read().decode()
                self.assertIn("New project", home)
                created = _post(
                    base + "/api/projects",
                    {
                        "name": "Northwind",
                        "program": "Northwind",
                        "authorization": "Authorized fictional engagement",
                        "seeds": ["https://app.northwind.test"],
                        "include": ["*.northwind.test"],
                        "exclude": ["payments.northwind.test"],
                        "network": False,
                    },
                )
                self.assertEqual(created["slug"], "northwind")
                page = urllib.request.urlopen(base + "/projects/northwind").read().decode()
                self.assertIn("Discover hosts", page)
                self.assertIn("/api/projects/northwind", page)
                _post(base + "/api/projects/northwind/run", {})
                status = {}
                for _ in range(40):
                    status = json.load(urllib.request.urlopen(base + "/api/projects/northwind/run"))
                    if status["state"] in {"completed", "failed"}:
                        break
                    time.sleep(0.25)
                self.assertEqual(status["state"], "completed", status)
                self.assertIn("case.json", status["files"])
                self.assertIn("hosts.txt", status["files"])
                case = json.load(urllib.request.urlopen(base + "/api/projects/northwind/files/case.json"))
                self.assertEqual(case["engagement"]["name"], "Northwind")
                hosts = urllib.request.urlopen(base + "/api/projects/northwind/files/hosts.txt").read().decode()
                self.assertIn("app.northwind.test", hosts)
                bootstrap = json.load(urllib.request.urlopen(base + "/api/projects/northwind/bootstrap"))
                self.assertEqual(bootstrap["project"]["slug"], "northwind")
                self.assertGreaterEqual(bootstrap["summary"]["assets"], 1)
            finally:
                server.shutdown()
                server.server_close()


def _post(url: str, payload: dict) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise AssertionError(exc.read().decode()) from exc


if __name__ == "__main__":
    unittest.main()
