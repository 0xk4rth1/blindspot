import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory

from blindspot.config import ConfigError
from blindspot.dashboard.product import AppServer
from blindspot.projects import create_project


class ProjectTests(unittest.TestCase):
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
                self.assertIn("Run collection", page)
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
