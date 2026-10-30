import tempfile
import unittest
from pathlib import Path

from blindspot.adapters.external import parse_dnsx, parse_host_lines, parse_httpx
from blindspot.db import Database
from blindspot.intelligence.engine import build_hypotheses
from blindspot.normalize import strip_url
from blindspot.parsekit import cookie_flags, extract_js, parse_openapi, parse_spf
from blindspot.safety import PolicyError, is_blocked_target, sanitize_tool_args, secret_fingerprints
from blindspot.scope import ScopeManager


class ScopeTests(unittest.TestCase):
    def test_exclude_wins_and_wildcard_includes_apex(self) -> None:
        scope = ScopeManager.from_lists(["*.northwind.test", "northwind.test"], ["payments.northwind.test"])
        self.assertTrue(scope.allows_host("northwind.test"))
        self.assertTrue(scope.allows_host("app.northwind.test"))
        self.assertFalse(scope.allows_host("payments.northwind.test"))
        self.assertFalse(scope.allows_url("https://payments.northwind.test/pay"))

    def test_url_prefix_does_not_allow_sibling_port_or_path(self) -> None:
        scope = ScopeManager.from_lists(["https://api.northwind.test/v1"])
        self.assertTrue(scope.allows_url("https://api.northwind.test/v1/users"))
        self.assertFalse(scope.allows_url("https://api.northwind.test/admin"))
        self.assertFalse(scope.allows_url("http://api.northwind.test/v1/users"))
        self.assertFalse(scope.allows_url("https://api.northwind.test:8443/v1/users"))
        self.assertEqual(scope.enumeration_domains(), [])

    def test_metadata_is_never_in_scope(self) -> None:
        scope = ScopeManager.from_lists(["169.254.169.254", "metadata.google.internal"])
        self.assertTrue(is_blocked_target("169.254.169.254"))
        self.assertFalse(scope.allows_host("169.254.169.254"))
        self.assertFalse(scope.allows_url("http://169.254.169.254/latest/meta-data"))
        with self.assertRaises(PolicyError):
            scope.assert_seeds(["http://169.254.169.254/"])


class ParserTests(unittest.TestCase):
    def test_query_values_and_secrets_are_not_kept(self) -> None:
        self.assertNotIn("sekret", strip_url("https://app.test/a?token=sekret"))
        findings, redacted = secret_fingerprints('const key = "AKIAIOSFODNN7EXAMPLE";')
        self.assertEqual(findings[0]["pattern"], "aws_access_key_id")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redacted)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", str(findings))
        facts = extract_js(
            'fetch("/api/users?id=1"); const featureFlags = {"newBilling": true};\n'
            '//# sourceMappingURL=app.js.map\n'
            'const key = "AKIAIOSFODNN7EXAMPLE";'
        )
        self.assertIn("/api/users?id=1", facts.endpoints)
        self.assertIn("newBilling", facts.feature_flags)
        self.assertEqual(facts.sourcemap, "app.js.map")
        self.assertEqual(facts.secrets[0]["pattern"], "aws_access_key_id")

    def test_cookie_flags_drop_the_value(self) -> None:
        parsed = cookie_flags("session=supersecret; HttpOnly; Secure; SameSite=Lax")
        self.assertEqual(parsed["name"], "session")
        self.assertTrue(parsed["httponly"])
        self.assertNotIn("supersecret", str(parsed))

    def test_openapi_parameters_and_security(self) -> None:
        operations = parse_openapi(
            {
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
        )
        by_path = {item.path: item for item in operations}
        self.assertEqual(by_path["/admin/export"].security, [])
        self.assertEqual(by_path["/api/users"].parameters[0]["name"], "id")

    def test_spf_and_tool_args(self) -> None:
        parsed = parse_spf("v=spf1 include:_spf.google.com ip4:203.0.113.5 -all")
        self.assertEqual(parsed["includes"], ["_spf.google.com"])
        kept, dropped = sanitize_tool_args(["-silent", "-brute", "-w", "names.txt"])
        self.assertEqual(kept, ["-silent"])
        self.assertEqual(dropped, ["-brute", "-w", "names.txt"])

    def test_external_parsers(self) -> None:
        self.assertEqual(parse_host_lines("a.test\nb.test\n"), ["a.test", "b.test"])
        self.assertEqual(parse_dnsx("a.test [A] 203.0.113.8")[0], ("a.test", "A", "203.0.113.8"))
        self.assertEqual(parse_httpx('{"url":"https://a.test","status_code":200}')[0]["status_code"], 200)


class CaseTests(unittest.TestCase):
    def test_events_are_not_overwritten_and_review_status_sticks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "case.sqlite")
            engagement = db.ensure_engagement("northwind", "program", "authorized")
            first = db.add_event(
                engagement,
                source="wayback",
                kind="historical_url",
                subject="app.northwind.test",
                value="https://app.northwind.test/old",
                confidence=0.5,
                job_id=1,
                meta={"timestamp": "2019"},
            )
            second = db.add_event(
                engagement,
                source="wayback",
                kind="historical_url",
                subject="app.northwind.test",
                value="https://app.northwind.test/old",
                confidence=0.5,
                job_id=2,
                meta={"timestamp": "2019"},
            )
            self.assertTrue(first)
            self.assertFalse(second)
            db.upsert_surface(
                engagement,
                "https://app.northwind.test/old",
                source="wayback",
                status=200,
                observed_at="2019-01-01T00:00:00+00:00",
            )
            db.upsert_surface(
                engagement,
                "https://app.northwind.test/old",
                source="wayback",
                status=200,
                observed_at="2020-01-01T00:00:00+00:00",
            )
            row = db.list_surface(engagement)[0]
            self.assertEqual(row["first_seen"], "2019-01-01T00:00:00+00:00")
            self.assertEqual(row["seen_count"], 2)
            db.upsert_hypothesis(
                engagement,
                dedupe_key="demo:1",
                title="Review host",
                category="new_asset",
                subject="app.northwind.test",
                summary="Review the new host manually.",
                priority=40,
                confidence=0.5,
                evidence=[{"source": "ct"}],
            )
            hypothesis_id = db.list_hypotheses(engagement)[0]["id"]
            db.set_hypothesis_status(engagement, hypothesis_id, "dismissed")
            db.upsert_hypothesis(
                engagement,
                dedupe_key="demo:1",
                title="Review host",
                category="new_asset",
                subject="app.northwind.test",
                summary="Review the new host manually.",
                priority=70,
                confidence=0.8,
                evidence=[{"source": "ct"}, {"source": "dns"}],
            )
            updated = db.list_hypotheses(engagement)[0]
            self.assertEqual(updated["status"], "dismissed")
            self.assertEqual(updated["priority"], 70)
            db.close()

    def test_hypotheses_from_a_small_case(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "case.sqlite")
            engagement = db.ensure_engagement("northwind", "program", "authorized")
            db.add_event(
                engagement,
                source="openapi",
                kind="api_operation",
                subject="app.northwind.test",
                value="POST /admin/export",
                confidence=0.8,
                job_id=1,
                evidence="https://app.northwind.test/openapi.json",
                meta={"method": "POST", "path": "/admin/export", "security": [], "parameters": []},
            )
            drafts = build_hypotheses(db, engagement)
            categories = {item["category"] for item in drafts}
            self.assertIn("unauthenticated_admin_spec", categories)
            blob = str(drafts)
            self.assertNotIn("payload", blob.lower())
            db.close()


if __name__ == "__main__":
    unittest.main()
