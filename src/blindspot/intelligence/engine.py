"""Intelligence is read-only over the case file. It does not fetch or attack."""

from __future__ import annotations

from collections import defaultdict

from blindspot.intelligence.leads import build_hypotheses, family_key, priority_for, record_version_shifts
from blindspot.parsekit import classify_endpoint
from blindspot.stages.result import StageResult

__all__ = ["ChangeDetectStage", "ClassifyStage", "CorrelateStage", "HypothesizeStage", "build_hypotheses", "priority_for"]


class ChangeDetectStage:
    name = "change_detect"

    async def execute(self, ctx) -> StageResult:
        stages = set(ctx.selected_stages)
        count = ctx.db.detect_changes(ctx.engagement_id, ctx.job_id, stages)
        record_version_shifts(ctx.db, ctx.engagement_id, ctx.job_id)
        return StageResult(self.name, inserted=count)


class ClassifyStage:
    name = "classify"

    async def execute(self, ctx) -> StageResult:
        inserted = 0
        parameters = ctx.db.list_parameters(ctx.engagement_id)
        by_path: dict[tuple[str, str], list[str]] = {}
        for row in parameters:
            by_path.setdefault((row["host"], row["templated_path"]), []).append(row["name"])
        seen: set[tuple[str, str, str]] = set()
        for row in ctx.db.list_surface(ctx.engagement_id):
            key = (row["host"], row["method"], row["templated_path"])
            if key in seen:
                continue
            seen.add(key)
            names = by_path.get((row["host"], row["templated_path"]), [])
            classification, functionality = classify_endpoint(row["templated_path"], names)
            ctx.db.upsert_endpoint(
                ctx.engagement_id,
                host=row["host"],
                method=row["method"],
                templated=row["templated_path"],
                classification=classification,
                functionality=functionality,
                source=row["last_source"],
            )
            inserted += 1
        for event in ctx.db.list_events(ctx.engagement_id, kind="js_endpoint", limit=1000):
            host = event["subject"]
            path = event["value"]
            names = by_path.get((host, path), [])
            classification, functionality = classify_endpoint(path, names)
            ctx.db.upsert_endpoint(
                ctx.engagement_id,
                host=host,
                method="GET",
                templated=path,
                classification=classification,
                functionality=functionality,
                source="js_analysis",
            )
            inserted += 1
        return StageResult(self.name, inserted=inserted)


class CorrelateStage:
    name = "correlate"

    async def execute(self, ctx) -> StageResult:
        inserted = 0
        endpoints = ctx.db.list_endpoints(ctx.engagement_id)
        families: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for endpoint in endpoints:
            ctx.db.upsert_relationship(
                ctx.engagement_id,
                src=endpoint["host"],
                rel="serves",
                dst=f"{endpoint['method']} {endpoint['templated_path']}",
                source=self.name,
                in_scope_dst=True,
            )
            inserted += 1
            parent = family_key(endpoint["templated_path"])
            if parent:
                families[(endpoint["host"], parent)].append(endpoint)
        for (host, parent), members in families.items():
            paths = {item["templated_path"] for item in members}
            if len(paths) < 2:
                continue
            for member in members:
                ctx.db.upsert_relationship(
                    ctx.engagement_id,
                    src=f"{host}{parent}",
                    rel="nests",
                    dst=f"{member['method']} {member['templated_path']}",
                    source=self.name,
                    in_scope_dst=True,
                )
                inserted += 1
        for tech in ctx.db.list_technologies(ctx.engagement_id):
            label = tech["name"] if not tech["version"] else f"{tech['name']} {tech['version']}"
            ctx.db.upsert_relationship(
                ctx.engagement_id,
                src=tech["host"],
                rel="technology",
                dst=label,
                source=self.name,
                evidence=tech["source"],
                in_scope_dst=False,
            )
            inserted += 1
        for parameter in ctx.db.list_parameters(ctx.engagement_id):
            ctx.db.upsert_relationship(
                ctx.engagement_id,
                src=f"{parameter['host']}{parameter['templated_path']}",
                rel="parameter",
                dst=f"{parameter['location']}:{parameter['name']}",
                source=self.name,
                in_scope_dst=True,
            )
            inserted += 1
        return StageResult(self.name, inserted=inserted)


class HypothesizeStage:
    name = "hypothesize"

    async def execute(self, ctx) -> StageResult:
        drafts = build_hypotheses(ctx.db, ctx.engagement_id)
        active = set()
        for draft in drafts:
            ctx.db.upsert_hypothesis(ctx.engagement_id, **draft)
            active.add(draft["dedupe_key"])
        ctx.db.retire_unmentioned(ctx.engagement_id, active)
        return StageResult(self.name, inserted=len(drafts))
