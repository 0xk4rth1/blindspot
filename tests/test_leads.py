import asyncio
import tempfile
import unittest
from pathlib import Path

from blindspot.db import Database
from blindspot.gate import RequestAudit, alias_block_reason, evaluate_redirect
from blindspot.http_client import FetchResult, ProviderHttp, TargetHttp
from blindspot.intake import Intake
from blindspot.intelligence.engine import build_hypotheses
from blindspot.intelligence.leads import priority_for, record_version_shifts
from blindspot.normalize import host_from_url
from blindspot.safety import PolicyError
from blindspot.scope import ScopeManager

HOST = "api.northwind.test"
ORG = [
    "/api/organizations/{id}",
    "/api/organizations/{id}/members",
    "/api/organizations/{id}/roles",
    "/api/organizations/{id}/billing",
]


def _ok(url, method, headers, timeout, max_bytes):
    return FetchResult(url=url, status=204, headers=[], body=b"")


class LeadTests(unittest.TestCase):
    def test_speculative_priority_cannot_outrank_strong_evidence(self) -> None:
        speculative = priority_for("exposed_secret_pattern", 0.99, "speculative")
        strong = priority_for("exposed_secret_pattern", 0.84, "strong")
        self.assertLessEqual(speculative, 45)
        self.assertGreater(strong, speculative)

    def test_organization_routes_become_one_tenant_lead(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "case.sqlite")
            engagement = db.ensure_engagement("northwind", "program", "authorized")
            for path in ORG:
                db.upsert_endpoint(
                    engagement,
                    host=HOST,
                    method="GET",
                    templated=path,
                    classification="api",
                    functionality="organization",
                    source="js_analysis",
                )
                db.add_event(
                    engagement,
                    source="js_analysis",
                    kind="js_endpoint",
                    subject=HOST,
                    value=path,
                    confidence=0.7,
                    job_id=1,
                    evidence="https://api.northwind.test/app.js",
                )
            drafts = [item for item in build_hypotheses(db, engagement) if item["category"] == "tenant_boundary"]
            self.assertEqual(len(drafts), 1)
            lead = drafts[0]
            blob = " ".join(lead["evidence"]["endpoints"])
            for path in ORG:
                self.assertIn(path, blob)
            event_ids = {item["event_id"] for item in lead["evidence"]["observations"]}
            self.assertEqual(event_ids, {1, 2, 3, 4})
            self.assertIn("authorization boundary", lead["validation_steps"])
            db.close()

    def test_one_script_is_one_lead_and_admin_spec_replaces_the_generic_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "case.sqlite")
            engagement = db.ensure_engagement("northwind", "program", "authorized")
            script = "https://app.northwind.test/app.js"
            db.add_event(
                engagement,
                source="js_analysis",
                kind="js_endpoint",
                subject="app.northwind.test",
                value="/api/users",
                confidence=0.6,
                job_id=1,
                evidence=script,
            )
            db.add_event(
                engagement,
                source="js_analysis",
                kind="feature_flag",
                subject="app.northwind.test",
                value="newBilling",
                confidence=0.5,
                job_id=1,
                evidence=script,
            )
            db.add_event(
                engagement,
                source="js_analysis",
                kind="sourcemap_url",
                subject=script,
                value="https://app.northwind.test/app.js.map",
                confidence=0.8,
                job_id=1,
                evidence=script,
            )
            db.add_event(
                engagement,
                source="sourcemap",
                kind="source_path",
                subject="https://app.northwind.test/app.js.map",
                value="src/admin/Export.ts",
                confidence=0.7,
                job_id=1,
                evidence="https://app.northwind.test/app.js.map",
            )
            db.upsert_endpoint(
                engagement,
                host="app.northwind.test",
                method="GET",
                templated="/admin/export",
                classification="admin",
                functionality="admin",
                source="crawl",
            )
            db.add_event(
                engagement,
                source="openapi",
                kind="api_operation",
                subject="app.northwind.test",
                value="POST /admin/export",
                confidence=0.8,
                job_id=1,
                meta={"method": "POST", "path": "/admin/export", "security": [], "parameters": []},
            )
            drafts = build_hypotheses(db, engagement)
            categories = [item["category"] for item in drafts]
            self.assertEqual(categories.count("client_bundle"), 1)
            self.assertNotIn("feature_exposure", categories)
            self.assertNotIn("admin_surface", categories)
            bundle = next(item for item in drafts if item["category"] == "client_bundle")
            kinds = {item["kind"] for item in bundle["evidence"]["observations"]}
            self.assertTrue({"js_endpoint", "feature_flag", "source_path"} <= kinds)
            self.assertTrue(all(item.get("event_id") for item in bundle["evidence"]["observations"]))
            db.add_change(engagement, 1, "added", "domain:app.northwind.test", "", "app.northwind.test", "change_detect")
            db.upsert_asset(
                engagement,
                "domain",
                "app.northwind.test",
                in_scope=True,
                source="js_analysis",
                confidence=0.6,
                job_id=1,
            )
            again = build_hypotheses(db, engagement)
            subjects = {item["subject"] for item in again if item["category"] == "new_asset"}
            self.assertNotIn("app.northwind.test", subjects)
            db.close()

    def test_historical_api_generation_is_one_lead(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "case.sqlite")
            engagement = db.ensure_engagement("northwind", "program", "authorized")
            db.upsert_surface(engagement, "https://api.northwind.test/v1/users", source="wayback", status=200)
            db.upsert_surface(engagement, "https://api.northwind.test/v1/orders", source="wayback", status=200)
            db.upsert_surface(engagement, "https://api.northwind.test/v2/users", source="http_probe", status=200)
            db.upsert_surface(engagement, "https://api.northwind.test/blog/post", source="wayback", status=200)
            record_version_shifts(db, engagement, 1)
            shifts = [row for row in db.list_changes(engagement) if row["change_type"] == "functionality_shifted"]
            self.assertEqual(len(shifts), 1)
            self.assertIn("/v2", shifts[0]["after_value"])
            historical = [
                item for item in build_hypotheses(db, engagement) if item["category"] == "historical_functionality"
            ]
            self.assertEqual(len(historical), 1)
            self.assertIn("/v1/users", " ".join(historical[0]["evidence"]["endpoints"]))
            self.assertIn("/v1/orders", " ".join(historical[0]["evidence"]["endpoints"]))
            self.assertNotIn("/blog/post", " ".join(historical[0]["evidence"]["endpoints"]))
            db.close()

    def test_reviewed_leads_stay_and_stale_queued_leads_leave(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "case.sqlite")
            engagement = db.ensure_engagement("northwind", "program", "authorized")
            db.upsert_hypothesis(
                engagement,
                dedupe_key="retired_surface:old",
                title="Old missing URL",
                category="retired_surface",
                subject="https://app.northwind.test/old",
                summary="This URL was missing.",
                priority=40,
                confidence=0.4,
                evidence=[],
            )
            kept = db.upsert_hypothesis(
                engagement,
                dedupe_key="demo:kept",
                title="Reviewed",
                category="new_asset",
                subject="app.northwind.test",
                summary="Already reviewed.",
                priority=20,
                confidence=0.4,
                evidence=[],
            )
            db.set_hypothesis_status(engagement, kept, "dismissed")
            db.retire_unmentioned(engagement, set())
            rows = {row["dedupe_key"]: row["status"] for row in db.list_hypotheses(engagement)}
            self.assertEqual(rows["retired_surface:old"], "superseded")
            self.assertEqual(rows["demo:kept"], "dismissed")
            db.close()


class BoundaryTests(unittest.TestCase):
    def test_disabled_network_never_calls_transport(self) -> None:
        calls = []

        def transport(*args, **kwargs):
            calls.append(args)
            raise AssertionError("transport was called")

        scope = ScopeManager.from_lists(["https://app.northwind.test"])
        client = TargetHttp(
            scope,
            timeout=1,
            delay_ms=0,
            max_bytes=1000,
            network_enabled=False,
            transport=transport,
        )
        with self.assertRaises(PolicyError):
            asyncio.run(client.get("https://app.northwind.test/admin"))
        self.assertEqual(calls, [])
        provider = ProviderHttp(
            {"https://crt.sh"},
            timeout=1,
            delay_ms=0,
            max_bytes=1000,
            network_enabled=False,
            transport=transport,
        )
        with self.assertRaises(PolicyError):
            asyncio.run(provider.get("https://crt.sh/?q=app"))
        self.assertEqual(calls, [])

    def test_cname_metadata_and_provider_destinations_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "case.sqlite")
            engagement = db.ensure_engagement("northwind", "program", "authorized")
            scope = ScopeManager.from_lists(["*.northwind.test"])
            db.upsert_relationship(
                engagement,
                src="app.northwind.test",
                rel="cname",
                dst="evil.test",
                source="dns_resolve",
                in_scope_dst=False,
            )
            calls = []

            def transport(*args, **kwargs):
                calls.append(args[0] if args else "")
                return _ok(*args)

            audit = RequestAudit(db, engagement, 1)
            client = TargetHttp(
                scope,
                timeout=1,
                delay_ms=0,
                max_bytes=1000,
                network_enabled=True,
                transport=transport,
                guard=lambda url: alias_block_reason(scope, host_from_url(url), db.list_relationships(engagement)),
                auditor=audit,
            )
            with self.assertRaises(PolicyError):
                asyncio.run(client.get("https://app.northwind.test/"))
            self.assertEqual(calls, [])
            self.assertEqual(db.list_requests(engagement, "rejected")[-1]["reason"], "cname target evil.test is out of scope")

            db.upsert_relationship(
                engagement,
                src="edge.northwind.test",
                rel="resolves_to",
                dst="169.254.169.254",
                source="dns_resolve",
            )
            with self.assertRaises(PolicyError):
                asyncio.run(client.get("https://edge.northwind.test/"))
            self.assertEqual(calls, [])

            db.upsert_relationship(
                engagement,
                src="api.northwind.test",
                rel="cname",
                dst="app.northwind.test",
                source="dns_resolve",
                in_scope_dst=True,
            )
            result = asyncio.run(client.get("https://api.northwind.test/health"))
            self.assertEqual(result.status, 204)
            self.assertEqual(calls, ["https://api.northwind.test/health"])

            provider = ProviderHttp(
                {"https://crt.sh"},
                timeout=1,
                delay_ms=0,
                max_bytes=1000,
                network_enabled=True,
                transport=transport,
                auditor=audit,
            )
            with self.assertRaises(PolicyError):
                asyncio.run(provider.get("http://169.254.169.254/latest/meta-data"))
            self.assertEqual(calls, ["https://api.northwind.test/health"])
            decision, _target, reason = evaluate_redirect(
                scope,
                "https://app.northwind.test/",
                "http://169.254.169.254/latest/meta-data",
            )
            self.assertEqual(decision, "rejected")
            self.assertIn("metadata", reason)
            offscope, _target, _reason = evaluate_redirect(scope, "https://app.northwind.test/", "https://evil.test/next")
            self.assertEqual(offscope, "rejected")
            db.close()

    def test_historical_url_cannot_bypass_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "case.sqlite")
            engagement = db.ensure_engagement("northwind", "program", "authorized")
            scope = ScopeManager.from_lists(["*.northwind.test"])
            intake = Intake(db, scope, engagement, 1, max_urls=20)
            intake.auditor = RequestAudit(db, engagement, 1)
            self.assertEqual(
                intake.surface("https://evil.test/legacy/export", source="wayback", confidence=0.4),
                "",
            )
            self.assertEqual(db.list_surface(engagement), [])
            rejected = db.list_requests(engagement, "rejected")
            self.assertEqual(len(rejected), 1)
            self.assertIn("evil.test", rejected[0]["url"])
            db.close()


if __name__ == "__main__":
    unittest.main()
