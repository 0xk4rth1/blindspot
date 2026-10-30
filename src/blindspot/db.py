"""SQLite case file.

Events are append-only. Projections such as assets and surface URLs update
first-seen and last-seen, and older event rows are left in place.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from blindspot.normalize import content_hash, normalize_host, strip_url, template_path
from blindspot.scope import ScopeManager, ScopeRule

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS engagements (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  program TEXT NOT NULL DEFAULT '',
  authorization TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scope_rules (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id),
  action TEXT NOT NULL,
  kind TEXT NOT NULL,
  pattern TEXT NOT NULL,
  UNIQUE(engagement_id, action, kind, pattern)
);

CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id),
  status TEXT NOT NULL,
  selected_stages TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  error TEXT,
  stats_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS job_logs (
  id INTEGER PRIMARY KEY,
  job_id INTEGER NOT NULL REFERENCES jobs(id),
  level TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL REFERENCES engagements(id),
  asset_type TEXT NOT NULL,
  value TEXT NOT NULL,
  normalized TEXT NOT NULL,
  in_scope INTEGER NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  UNIQUE(engagement_id, asset_type, normalized)
);

CREATE TABLE IF NOT EXISTS asset_sources (
  id INTEGER PRIMARY KEY,
  asset_id INTEGER NOT NULL REFERENCES assets(id),
  job_id INTEGER,
  source TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '',
  confidence REAL NOT NULL,
  observed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL,
  job_id INTEGER,
  source TEXT NOT NULL,
  kind TEXT NOT NULL,
  subject TEXT NOT NULL DEFAULT '',
  value TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '',
  confidence REAL NOT NULL,
  content_hash TEXT NOT NULL,
  meta_json TEXT NOT NULL DEFAULT '{}',
  observed_at TEXT NOT NULL,
  UNIQUE(engagement_id, content_hash)
);

CREATE TABLE IF NOT EXISTS surface_urls (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL,
  normalized TEXT NOT NULL,
  url TEXT NOT NULL,
  host TEXT NOT NULL,
  method TEXT NOT NULL DEFAULT 'GET',
  templated_path TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  first_source TEXT NOT NULL,
  last_source TEXT NOT NULL,
  last_status INTEGER,
  seen_count INTEGER NOT NULL DEFAULT 1,
  UNIQUE(engagement_id, method, normalized)
);

CREATE TABLE IF NOT EXISTS endpoints (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL,
  host TEXT NOT NULL,
  method TEXT NOT NULL,
  templated_path TEXT NOT NULL,
  classification TEXT NOT NULL,
  functionality TEXT NOT NULL,
  sources TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  UNIQUE(engagement_id, host, method, templated_path)
);

CREATE TABLE IF NOT EXISTS parameters (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL,
  host TEXT NOT NULL,
  templated_path TEXT NOT NULL,
  name TEXT NOT NULL,
  location TEXT NOT NULL,
  source TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  UNIQUE(engagement_id, host, templated_path, name, location)
);

CREATE TABLE IF NOT EXISTS technologies (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL,
  host TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL,
  confidence REAL NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  UNIQUE(engagement_id, host, name, version)
);

CREATE TABLE IF NOT EXISTS relationships (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL,
  src TEXT NOT NULL,
  rel TEXT NOT NULL,
  dst TEXT NOT NULL,
  source TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '',
  in_scope_dst INTEGER NOT NULL DEFAULT 0,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  UNIQUE(engagement_id, src, rel, dst)
);

CREATE TABLE IF NOT EXISTS changes (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL,
  job_id INTEGER,
  change_type TEXT NOT NULL,
  subject TEXT NOT NULL,
  before_value TEXT NOT NULL DEFAULT '',
  after_value TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL,
  detected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hypotheses (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL,
  dedupe_key TEXT NOT NULL,
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  subject TEXT NOT NULL,
  summary TEXT NOT NULL,
  priority INTEGER NOT NULL,
  confidence REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  evidence_json TEXT NOT NULL DEFAULT '[]',
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  UNIQUE(engagement_id, dedupe_key)
);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL,
  job_id INTEGER,
  message TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS request_log (
  id INTEGER PRIMARY KEY,
  engagement_id INTEGER NOT NULL,
  job_id INTEGER,
  stage TEXT NOT NULL DEFAULT '',
  url TEXT NOT NULL,
  decision TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_kind ON events(engagement_id, kind);
CREATE INDEX IF NOT EXISTS idx_assets_scope ON assets(engagement_id, in_scope);
CREATE INDEX IF NOT EXISTS idx_changes_job ON changes(job_id);
CREATE INDEX IF NOT EXISTS idx_request_log_job ON request_log(job_id, decision);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(hypotheses)")}
        additions = {
            "confidence_band": "TEXT NOT NULL DEFAULT 'supported'",
            "rationale": "TEXT NOT NULL DEFAULT ''",
            "limitations": "TEXT NOT NULL DEFAULT ''",
            "validation_steps": "TEXT NOT NULL DEFAULT ''",
        }
        for name, declaration in additions.items():
            if name not in columns:
                self._conn.execute(f"ALTER TABLE hypotheses ADD COLUMN {name} {declaration}")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def ensure_engagement(self, name: str, program: str, authorization: str) -> int:
        now = utcnow()
        with self._lock:
            row = self._conn.execute("SELECT id FROM engagements WHERE name = ?", (name,)).fetchone()
            if row:
                self._conn.execute(
                    "UPDATE engagements SET program = ?, authorization = ? WHERE id = ?",
                    (program, authorization, row["id"]),
                )
                self._conn.commit()
                return int(row["id"])
            cursor = self._conn.execute(
                """
                INSERT INTO engagements(name, program, authorization, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (name, program, authorization, now),
            )
            self._conn.commit()
            return int(cursor.lastrowid)

    def replace_scope(self, engagement_id: int, rules: list[ScopeRule]) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM scope_rules WHERE engagement_id = ?", (engagement_id,))
            self._conn.executemany(
                """
                INSERT INTO scope_rules(engagement_id, action, kind, pattern)
                VALUES (?, ?, ?, ?)
                """,
                [(engagement_id, rule.action, rule.kind, rule.pattern) for rule in rules],
            )
            self._conn.commit()

    def apply_scope(self, engagement_id: int, scope: ScopeManager, job_id: int) -> None:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, normalized, in_scope FROM assets
                WHERE engagement_id = ? AND asset_type IN ('domain', 'host', 'ip')
                """,
                (engagement_id,),
            ).fetchall()
            now = utcnow()
            for row in rows:
                allowed = 1 if scope.allows_host(row["normalized"]) else 0
                if int(row["in_scope"]) == allowed:
                    continue
                self._conn.execute("UPDATE assets SET in_scope = ? WHERE id = ?", (allowed, row["id"]))
                self._insert_change(
                    engagement_id,
                    job_id,
                    "scope_included" if allowed else "scope_excluded",
                    row["normalized"],
                    str(row["in_scope"]),
                    str(allowed),
                    "scope",
                    now,
                )
            self._conn.commit()

    def create_job(self, engagement_id: int, stages: list[str]) -> int:
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO jobs(engagement_id, status, selected_stages, started_at, stats_json)
                VALUES (?, 'running', ?, ?, '{}')
                """,
                (engagement_id, ",".join(stages), utcnow()),
            )
            self._conn.commit()
            return int(cursor.lastrowid)

    def finish_job(self, job_id: int, status: str, error: str = "", stats: dict | None = None) -> None:
        with self._lock:
            self._conn.execute(
                """
                UPDATE jobs
                SET status = ?, finished_at = ?, error = ?, stats_json = ?
                WHERE id = ?
                """,
                (status, utcnow(), error[:2000], json.dumps(stats or {}), job_id),
            )
            self._conn.commit()

    def add_log(self, job_id: int, level: str, message: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO job_logs(job_id, level, message, created_at) VALUES (?, ?, ?, ?)",
                (job_id, level, message[:2000], utcnow()),
            )
            self._conn.commit()

    def upsert_asset(
        self,
        engagement_id: int,
        asset_type: str,
        value: str,
        *,
        in_scope: bool,
        source: str,
        confidence: float,
        job_id: int | None,
        evidence: str = "",
        observed_at: str | None = None,
    ) -> int:
        now = observed_at or utcnow()
        normalized = normalize_host(value) if asset_type in {"domain", "host", "ip", "external_name"} else value
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, first_seen, last_seen FROM assets
                WHERE engagement_id = ? AND asset_type = ? AND normalized = ?
                """,
                (engagement_id, asset_type, normalized),
            ).fetchone()
            if row:
                first = row["first_seen"] if row["first_seen"] <= now else now
                last = row["last_seen"] if row["last_seen"] >= now else now
                self._conn.execute(
                    "UPDATE assets SET first_seen = ?, last_seen = ?, in_scope = ?, active = 1 WHERE id = ?",
                    (first, last, 1 if in_scope else 0, row["id"]),
                )
                asset_id = int(row["id"])
            else:
                cursor = self._conn.execute(
                    """
                    INSERT INTO assets(
                      engagement_id, asset_type, value, normalized, in_scope, first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (engagement_id, asset_type, value, normalized, 1 if in_scope else 0, now, now),
                )
                asset_id = int(cursor.lastrowid)
            self._conn.execute(
                """
                INSERT INTO asset_sources(asset_id, job_id, source, evidence, confidence, observed_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (asset_id, job_id, source, evidence[:500], float(confidence), now),
            )
            self._conn.commit()
            return asset_id

    def add_event(
        self,
        engagement_id: int,
        *,
        source: str,
        kind: str,
        subject: str,
        value: str,
        confidence: float,
        job_id: int | None,
        evidence: str = "",
        meta: dict | None = None,
        observed_at: str | None = None,
    ) -> bool:
        meta = meta or {}
        digest = content_hash(
            {"source": source, "kind": kind, "subject": subject, "value": value, "meta": meta}
        )
        now = observed_at or utcnow()
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT OR IGNORE INTO events(
                  engagement_id, job_id, source, kind, subject, value, evidence,
                  confidence, content_hash, meta_json, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement_id,
                    job_id,
                    source,
                    kind,
                    subject[:500],
                    value[:2000],
                    evidence[:500],
                    float(confidence),
                    digest,
                    json.dumps(meta, sort_keys=True),
                    now,
                ),
            )
            self._conn.commit()
            return cursor.rowcount == 1

    def upsert_surface(
        self,
        engagement_id: int,
        url: str,
        *,
        source: str,
        status: int | None,
        observed_at: str | None = None,
        method: str = "GET",
    ) -> int | None:
        cleaned = strip_url(url)
        if not cleaned:
            return None
        from urllib.parse import urlsplit

        parts = urlsplit(cleaned)
        host = normalize_host(parts.hostname or "")
        path = template_path(parts.path or "/")
        now = observed_at or utcnow()
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, first_seen, last_seen, seen_count, last_status
                FROM surface_urls
                WHERE engagement_id = ? AND method = ? AND normalized = ?
                """,
                (engagement_id, method, cleaned),
            ).fetchone()
            if row:
                first = row["first_seen"] if row["first_seen"] <= now else now
                last = row["last_seen"] if row["last_seen"] >= now else now
                self._conn.execute(
                    """
                    UPDATE surface_urls
                    SET first_seen = ?, last_seen = ?, last_source = ?, last_status = ?, seen_count = ?
                    WHERE id = ?
                    """,
                    (
                        first,
                        last,
                        source,
                        status if status is not None else row["last_status"],
                        int(row["seen_count"]) + 1,
                        row["id"],
                    ),
                )
                self._conn.commit()
                return int(row["id"])
            cursor = self._conn.execute(
                """
                INSERT INTO surface_urls(
                  engagement_id, normalized, url, host, method, templated_path,
                  first_seen, last_seen, first_source, last_source, last_status, seen_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (engagement_id, cleaned, cleaned, host, method, path, now, now, source, source, status),
            )
            self._conn.commit()
            return int(cursor.lastrowid)

    def upsert_endpoint(
        self,
        engagement_id: int,
        *,
        host: str,
        method: str,
        templated: str,
        classification: str,
        functionality: str,
        source: str,
    ) -> int:
        now = utcnow()
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, sources, first_seen FROM endpoints
                WHERE engagement_id = ? AND host = ? AND method = ? AND templated_path = ?
                """,
                (engagement_id, host, method, templated),
            ).fetchone()
            if row:
                sources = {item for item in (row["sources"] or "").split(",") if item}
                sources.add(source)
                self._conn.execute(
                    """
                    UPDATE endpoints
                    SET classification = ?, functionality = ?, sources = ?, last_seen = ?
                    WHERE id = ?
                    """,
                    (classification, functionality, ",".join(sorted(sources)), now, row["id"]),
                )
                self._conn.commit()
                return int(row["id"])
            cursor = self._conn.execute(
                """
                INSERT INTO endpoints(
                  engagement_id, host, method, templated_path, classification, functionality,
                  sources, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (engagement_id, host, method, templated, classification, functionality, source, now, now),
            )
            self._conn.commit()
            return int(cursor.lastrowid)

    def upsert_parameter(
        self,
        engagement_id: int,
        *,
        host: str,
        templated: str,
        name: str,
        location: str,
        source: str,
    ) -> None:
        now = utcnow()
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, first_seen FROM parameters
                WHERE engagement_id = ? AND host = ? AND templated_path = ?
                  AND name = ? AND location = ?
                """,
                (engagement_id, host, templated, name, location),
            ).fetchone()
            if row:
                self._conn.execute(
                    "UPDATE parameters SET last_seen = ?, source = ? WHERE id = ?",
                    (now, source, row["id"]),
                )
            else:
                self._conn.execute(
                    """
                    INSERT INTO parameters(
                      engagement_id, host, templated_path, name, location, source, first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (engagement_id, host, templated, name, location, source, now, now),
                )
            self._conn.commit()

    def upsert_technology(
        self,
        engagement_id: int,
        *,
        host: str,
        name: str,
        version: str,
        source: str,
        confidence: float,
    ) -> None:
        now = utcnow()
        version = version or ""
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, first_seen, last_seen FROM technologies
                WHERE engagement_id = ? AND host = ? AND name = ? AND version = ?
                """,
                (engagement_id, host, name, version),
            ).fetchone()
            if row:
                first = row["first_seen"]
                last = now if now > row["last_seen"] else row["last_seen"]
                self._conn.execute(
                    "UPDATE technologies SET first_seen = ?, last_seen = ? WHERE id = ?",
                    (first, last, row["id"]),
                )
            else:
                self._conn.execute(
                    """
                    INSERT INTO technologies(
                      engagement_id, host, name, version, source, confidence, first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (engagement_id, host, name, version, source, float(confidence), now, now),
                )
            self._conn.commit()

    def upsert_relationship(
        self,
        engagement_id: int,
        *,
        src: str,
        rel: str,
        dst: str,
        source: str,
        evidence: str = "",
        in_scope_dst: bool = False,
    ) -> None:
        now = utcnow()
        with self._lock:
            row = self._conn.execute(
                """
                SELECT id, first_seen, last_seen FROM relationships
                WHERE engagement_id = ? AND src = ? AND rel = ? AND dst = ?
                """,
                (engagement_id, src, rel, dst),
            ).fetchone()
            if row:
                last = now if now > row["last_seen"] else row["last_seen"]
                self._conn.execute(
                    "UPDATE relationships SET last_seen = ?, in_scope_dst = ? WHERE id = ?",
                    (last, 1 if in_scope_dst else 0, row["id"]),
                )
            else:
                self._conn.execute(
                    """
                    INSERT INTO relationships(
                      engagement_id, src, rel, dst, source, evidence, in_scope_dst, first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (engagement_id, src, rel, dst, source, evidence[:500], 1 if in_scope_dst else 0, now, now),
                )
            self._conn.commit()

    def add_change(
        self,
        engagement_id: int,
        job_id: int | None,
        change_type: str,
        subject: str,
        before_value: str,
        after_value: str,
        source: str,
    ) -> None:
        with self._lock:
            self._insert_change(
                engagement_id,
                job_id,
                change_type,
                subject,
                before_value,
                after_value,
                source,
                utcnow(),
            )
            self._conn.commit()

    def _insert_change(
        self,
        engagement_id: int,
        job_id: int | None,
        change_type: str,
        subject: str,
        before_value: str,
        after_value: str,
        source: str,
        detected_at: str,
    ) -> None:
        exists = self._conn.execute(
            """
            SELECT 1 FROM changes
            WHERE engagement_id = ? AND job_id IS ? AND change_type = ?
              AND subject = ? AND before_value = ? AND after_value = ?
            """,
            (engagement_id, job_id, change_type, subject, before_value, after_value),
        ).fetchone()
        if exists:
            return
        self._conn.execute(
            """
            INSERT INTO changes(
              engagement_id, job_id, change_type, subject, before_value, after_value, source, detected_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (engagement_id, job_id, change_type, subject, before_value, after_value, source, detected_at),
        )

    def upsert_hypothesis(
        self,
        engagement_id: int,
        *,
        dedupe_key: str,
        title: str,
        category: str,
        subject: str,
        summary: str,
        priority: int,
        confidence: float,
        evidence: list | dict,
        confidence_band: str = "supported",
        rationale: str = "",
        limitations: str = "",
        validation_steps: str = "",
    ) -> int:
        now = utcnow()
        payload = json.dumps(evidence, sort_keys=True)
        with self._lock:
            row = self._conn.execute(
                "SELECT id, status FROM hypotheses WHERE engagement_id = ? AND dedupe_key = ?",
                (engagement_id, dedupe_key),
            ).fetchone()
            if row:
                self._conn.execute(
                    """
                    UPDATE hypotheses
                    SET title = ?, summary = ?, priority = ?, confidence = ?,
                        confidence_band = ?, rationale = ?, limitations = ?,
                        validation_steps = ?, evidence_json = ?, last_seen = ?
                    WHERE id = ?
                    """,
                    (
                        title,
                        summary,
                        int(priority),
                        float(confidence),
                        confidence_band,
                        rationale,
                        limitations,
                        validation_steps,
                        payload,
                        now,
                        row["id"],
                    ),
                )
                self._conn.commit()
                return int(row["id"])
            cursor = self._conn.execute(
                """
                INSERT INTO hypotheses(
                  engagement_id, dedupe_key, title, category, subject, summary,
                  priority, confidence, confidence_band, rationale, limitations,
                  validation_steps, status, evidence_json, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?)
                """,
                (
                    engagement_id,
                    dedupe_key,
                    title,
                    category,
                    subject,
                    summary,
                    int(priority),
                    float(confidence),
                    confidence_band,
                    rationale,
                    limitations,
                    validation_steps,
                    payload,
                    now,
                    now,
                ),
            )
            self._conn.commit()
            return int(cursor.lastrowid)

    def retire_unmentioned(self, engagement_id: int, active_keys: set[str]) -> int:
        """Hide queued leads that this run no longer supports. Reviewed statuses stay."""

        with self._lock:
            rows = self._conn.execute(
                "SELECT id, dedupe_key FROM hypotheses WHERE engagement_id = ? AND status = 'queued'",
                (engagement_id,),
            ).fetchall()
            retired = 0
            for row in rows:
                if row["dedupe_key"] in active_keys:
                    continue
                self._conn.execute(
                    "UPDATE hypotheses SET status = 'superseded' WHERE id = ?",
                    (row["id"],),
                )
                retired += 1
            self._conn.commit()
            return retired

    def log_request(
        self,
        engagement_id: int,
        job_id: int | None,
        stage: str,
        url: str,
        decision: str,
        reason: str = "",
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO request_log(engagement_id, job_id, stage, url, decision, reason, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (engagement_id, job_id, stage[:80], url[:1000], decision, reason[:300], utcnow()),
            )
            self._conn.commit()

    def list_requests(self, engagement_id: int, decision: str | None = None) -> list[dict]:
        if decision:
            return self._query(
                """
                SELECT * FROM request_log
                WHERE engagement_id = ? AND decision = ?
                ORDER BY id
                """,
                (engagement_id, decision),
            )
        return self._query(
            "SELECT * FROM request_log WHERE engagement_id = ? ORDER BY id",
            (engagement_id,),
        )

    def set_hypothesis_status(self, engagement_id: int, hypothesis_id: int, status: str) -> dict | None:
        if status not in {"queued", "accepted", "dismissed", "done"}:
            raise ValueError(f"unsupported status: {status}")
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM hypotheses WHERE engagement_id = ? AND id = ?",
                (engagement_id, hypothesis_id),
            ).fetchone()
            if not row:
                return None
            self._conn.execute(
                "UPDATE hypotheses SET status = ? WHERE id = ?",
                (status, hypothesis_id),
            )
            self._conn.commit()
        updated = self.list_hypotheses(engagement_id)
        return next((item for item in updated if item["id"] == hypothesis_id), None)

    def add_notification(self, engagement_id: int, job_id: int | None, message: str, payload: dict) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO notifications(engagement_id, job_id, message, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (engagement_id, job_id, message, json.dumps(payload), utcnow()),
            )
            self._conn.commit()

    def in_scope_hosts(self, engagement_id: int) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT normalized FROM assets
                WHERE engagement_id = ? AND in_scope = 1
                  AND asset_type IN ('domain', 'host', 'ip')
                ORDER BY normalized
                """,
                (engagement_id,),
            ).fetchall()
        return [row["normalized"] for row in rows]

    def detect_changes(self, engagement_id: int, job_id: int, stages_ran: set[str]) -> int:
        created = 0
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT a.asset_type, a.normalized
                FROM assets a
                JOIN asset_sources s ON s.asset_id = a.id
                WHERE a.engagement_id = ? AND s.job_id = ?
                  AND NOT EXISTS (
                    SELECT 1 FROM asset_sources earlier
                    WHERE earlier.asset_id = a.id AND earlier.job_id IS NOT NULL AND earlier.job_id != ?
                  )
                """,
                (engagement_id, job_id, job_id),
            ).fetchall()
            now = utcnow()
            for row in rows:
                before = created
                self._insert_change(
                    engagement_id,
                    job_id,
                    "added",
                    f"{row['asset_type']}:{row['normalized']}",
                    "",
                    row["normalized"],
                    "change_detect",
                    now,
                )
                created += 1 if created == before or True else 0
            # The insert helper dedupes. Count rows that exist for this job after inserts.
            tech_rows = self._conn.execute(
                """
                SELECT host, name, version FROM technologies
                WHERE engagement_id = ?
                ORDER BY host, name, first_seen
                """,
                (engagement_id,),
            ).fetchall()
            by_name: dict[tuple[str, str], list[str]] = {}
            for row in tech_rows:
                by_name.setdefault((row["host"], row["name"]), []).append(row["version"])
            for (host, name), versions in by_name.items():
                unique_versions = list(dict.fromkeys(versions))
                if len(unique_versions) < 2:
                    continue
                self._insert_change(
                    engagement_id,
                    job_id,
                    "modified",
                    f"technology:{host}:{name}",
                    unique_versions[0],
                    unique_versions[-1],
                    "change_detect",
                    now,
                )
            if "http_probe" in stages_ran:
                missing = self._conn.execute(
                    """
                    SELECT DISTINCT subject FROM events
                    WHERE engagement_id = ? AND kind = 'http_snapshot' AND job_id IS NOT NULL AND job_id != ?
                      AND subject NOT IN (
                        SELECT subject FROM events
                        WHERE engagement_id = ? AND kind = 'http_snapshot' AND job_id = ?
                      )
                    """,
                    (engagement_id, job_id, engagement_id, job_id),
                ).fetchall()
                for row in missing:
                    self._insert_change(
                        engagement_id,
                        job_id,
                        "not_observed",
                        row["subject"],
                        "http_snapshot",
                        "",
                        "change_detect",
                        now,
                    )
            self._conn.commit()
            count = self._conn.execute(
                "SELECT COUNT(*) AS n FROM changes WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        return int(count["n"]) if count else created

    def list_assets(self, engagement_id: int) -> list[dict]:
        return self._query(
            """
            SELECT a.*, GROUP_CONCAT(DISTINCT s.source) AS sources
            FROM assets a
            LEFT JOIN asset_sources s ON s.asset_id = a.id
            WHERE a.engagement_id = ?
            GROUP BY a.id
            ORDER BY a.in_scope DESC, a.asset_type, a.normalized
            """,
            (engagement_id,),
        )

    def list_surface(self, engagement_id: int, limit: int = 1000) -> list[dict]:
        return self._query(
            """
            SELECT * FROM surface_urls
            WHERE engagement_id = ?
            ORDER BY last_seen DESC
            LIMIT ?
            """,
            (engagement_id, limit),
        )

    def list_endpoints(self, engagement_id: int) -> list[dict]:
        return self._query(
            "SELECT * FROM endpoints WHERE engagement_id = ? ORDER BY functionality, templated_path",
            (engagement_id,),
        )

    def list_parameters(self, engagement_id: int) -> list[dict]:
        return self._query(
            "SELECT * FROM parameters WHERE engagement_id = ? ORDER BY templated_path, name",
            (engagement_id,),
        )

    def list_relationships(self, engagement_id: int) -> list[dict]:
        return self._query(
            "SELECT * FROM relationships WHERE engagement_id = ? ORDER BY rel, src",
            (engagement_id,),
        )

    def list_technologies(self, engagement_id: int) -> list[dict]:
        return self._query(
            "SELECT * FROM technologies WHERE engagement_id = ? ORDER BY host, name",
            (engagement_id,),
        )

    def list_changes(self, engagement_id: int, job_id: int | None = None) -> list[dict]:
        if job_id is None:
            return self._query(
                "SELECT * FROM changes WHERE engagement_id = ? ORDER BY id DESC",
                (engagement_id,),
            )
        return self._query(
            "SELECT * FROM changes WHERE engagement_id = ? AND job_id = ? ORDER BY id DESC",
            (engagement_id, job_id),
        )

    def list_hypotheses(self, engagement_id: int) -> list[dict]:
        rows = self._query(
            "SELECT * FROM hypotheses WHERE engagement_id = ? ORDER BY priority DESC, confidence DESC",
            (engagement_id,),
        )
        for row in rows:
            parsed = json.loads(row.pop("evidence_json") or "[]")
            row["evidence"] = parsed
            if isinstance(parsed, dict):
                row["observations"] = parsed.get("observations") or []
                row["endpoints"] = parsed.get("endpoints") or []
                row["assets"] = parsed.get("assets") or []
                row["rationale"] = row.get("rationale") or parsed.get("why_prioritized") or ""
                row["limitations"] = row.get("limitations") or parsed.get("limitations") or ""
            else:
                row["observations"] = parsed if isinstance(parsed, list) else []
                row["endpoints"] = []
                row["assets"] = []
        return rows

    def list_events(self, engagement_id: int, kind: str | None = None, limit: int = 500) -> list[dict]:
        if kind:
            rows = self._query(
                """
                SELECT * FROM events
                WHERE engagement_id = ? AND kind = ?
                ORDER BY id DESC LIMIT ?
                """,
                (engagement_id, kind, limit),
            )
        else:
            rows = self._query(
                "SELECT * FROM events WHERE engagement_id = ? ORDER BY id DESC LIMIT ?",
                (engagement_id, limit),
            )
        for row in rows:
            row["meta"] = json.loads(row.pop("meta_json") or "{}")
        return rows

    def list_jobs(self, engagement_id: int) -> list[dict]:
        rows = self._query(
            "SELECT * FROM jobs WHERE engagement_id = ? ORDER BY id DESC",
            (engagement_id,),
        )
        for row in rows:
            row["stats"] = json.loads(row.pop("stats_json") or "{}")
        return rows

    def job_logs(self, job_id: int, limit: int = 80) -> list[dict]:
        return self._query(
            "SELECT * FROM job_logs WHERE job_id = ? ORDER BY id DESC LIMIT ?",
            (job_id, limit),
        )

    def engagement_row(self, engagement_id: int) -> dict:
        rows = self._query("SELECT * FROM engagements WHERE id = ?", (engagement_id,))
        return rows[0]

    def summary(self, engagement_id: int) -> dict:
        def count(sql: str) -> int:
            with self._lock:
                row = self._conn.execute(sql, (engagement_id,)).fetchone()
            return int(row["n"])

        return {
            "assets": count("SELECT COUNT(*) AS n FROM assets WHERE engagement_id = ?"),
            "in_scope_hosts": count(
                "SELECT COUNT(*) AS n FROM assets WHERE engagement_id = ? AND in_scope = 1 AND asset_type IN ('domain','host','ip')"
            ),
            "surface_urls": count("SELECT COUNT(*) AS n FROM surface_urls WHERE engagement_id = ?"),
            "endpoints": count("SELECT COUNT(*) AS n FROM endpoints WHERE engagement_id = ?"),
            "parameters": count("SELECT COUNT(*) AS n FROM parameters WHERE engagement_id = ?"),
            "relationships": count("SELECT COUNT(*) AS n FROM relationships WHERE engagement_id = ?"),
            "technologies": count("SELECT COUNT(*) AS n FROM technologies WHERE engagement_id = ?"),
            "changes": count("SELECT COUNT(*) AS n FROM changes WHERE engagement_id = ?"),
            "hypotheses": count("SELECT COUNT(*) AS n FROM hypotheses WHERE engagement_id = ?"),
            "queued": count(
                "SELECT COUNT(*) AS n FROM hypotheses WHERE engagement_id = ? AND status = 'queued'"
            ),
            "events": count("SELECT COUNT(*) AS n FROM events WHERE engagement_id = ?"),
        }

    def _query(self, sql: str, params: tuple) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]
