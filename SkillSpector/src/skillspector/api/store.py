"""SQLite-backed persistence for API scan jobs."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

from .presentation import SEVERITY_ORDER, rule_family


def utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(UTC).isoformat()


class ApiStore:
    """Persistence layer for scan jobs, reports, findings, and scan events."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a configured SQLite connection."""
        conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
        finally:
            conn.close()

    def init_db(self) -> None:
        """Create database tables if they do not already exist."""
        with self.connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    status TEXT NOT NULL,
                    requested_formats TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    error TEXT,
                    risk_score INTEGER,
                    severity TEXT,
                    recommendation TEXT,
                    safe_to_install INTEGER,
                    findings_count INTEGER,
                    findings_by_severity TEXT,
                    findings_by_category TEXT,
                    available_reports TEXT,
                    scanner_version TEXT,
                    scan_mode TEXT,
                    llm_requested INTEGER NOT NULL DEFAULT 0,
                    llm_used INTEGER NOT NULL DEFAULT 0,
                    agent_review_provider TEXT,
                    agent_review_skill TEXT,
                    agent_review_prompt TEXT,
                    agent_review_model TEXT,
                    agent_review_requested INTEGER NOT NULL DEFAULT 0,
                    agent_review_used INTEGER NOT NULL DEFAULT 0,
                    agent_review_status TEXT,
                    agent_review_verdict TEXT,
                    agent_review_summary TEXT,
                    agent_review_json TEXT
                );

                CREATE TABLE IF NOT EXISTS scan_reports (
                    scan_id TEXT NOT NULL,
                    format TEXT NOT NULL,
                    content TEXT NOT NULL,
                    content_type TEXT NOT NULL,
                    PRIMARY KEY (scan_id, format),
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS scan_findings (
                    scan_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    category TEXT,
                    pattern TEXT,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    file TEXT NOT NULL,
                    start_line INTEGER NOT NULL,
                    end_line INTEGER,
                    payload_json TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS scan_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                );
                """
            )
            self._ensure_scan_column(conn, "agent_review_provider", "TEXT")
            self._ensure_scan_column(conn, "agent_review_skill", "TEXT")
            self._ensure_scan_column(conn, "agent_review_prompt", "TEXT")
            self._ensure_scan_column(conn, "agent_review_model", "TEXT")
            self._ensure_scan_column(conn, "agent_review_requested", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_scan_column(conn, "agent_review_used", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_scan_column(conn, "agent_review_status", "TEXT")
            self._ensure_scan_column(conn, "agent_review_verdict", "TEXT")
            self._ensure_scan_column(conn, "agent_review_summary", "TEXT")
            self._ensure_scan_column(conn, "agent_review_json", "TEXT")

    def create_scan(
        self,
        *,
        target: str,
        mode: str,
        requested_formats: list[str],
        agent_review_enabled: bool = False,
        agent_review_provider: str | None = None,
        agent_review_skill: str | None = None,
        agent_review_prompt: str | None = None,
        agent_review_model: str | None = None,
    ) -> dict[str, Any]:
        """Insert a new queued scan record and return it."""
        scan_id = str(uuid4())
        created_at = utc_now_iso()
        payload = {
            "scan_id": scan_id,
            "target": target,
            "mode": mode,
            "status": "queued",
            "requested_formats": requested_formats,
            "created_at": created_at,
            "agent_review_enabled": agent_review_enabled,
            "agent_review_provider": agent_review_provider,
        }
        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO scans (
                    id, target, mode, status, requested_formats, created_at,
                    agent_review_provider, agent_review_skill, agent_review_prompt, agent_review_model, agent_review_requested
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    target,
                    mode,
                    "queued",
                    json.dumps(requested_formats),
                    created_at,
                    agent_review_provider,
                    agent_review_skill,
                    agent_review_prompt,
                    agent_review_model,
                    1 if agent_review_enabled else 0,
                ),
            )
            self._record_event(conn, scan_id, "queued", "Scan queued for deterministic processing.")
        return payload

    def list_scans(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        status: str | None = None,
        mode: str | None = None,
        severity: str | None = None,
        target: str | None = None,
        scan_id: str | None = None,
        sort: str = "created_at_desc",
    ) -> dict[str, Any]:
        """List scans with pagination and lightweight filtering."""
        filters: list[str] = []
        params: list[Any] = []

        if status:
            filters.append("status = ?")
            params.append(status)
        if mode:
            filters.append("mode = ?")
            params.append(mode)
        if severity:
            filters.append("severity = ?")
            params.append(severity)
        if target:
            filters.append("target LIKE ?")
            params.append(f"%{target}%")
        if scan_id:
            filters.append("id LIKE ?")
            params.append(f"%{scan_id}%")

        where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
        order_by = {
            "created_at_asc": "created_at ASC",
            "risk_score_desc": "risk_score DESC, created_at DESC",
            "risk_score_asc": "risk_score ASC, created_at DESC",
            "severity_desc": "CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END ASC, created_at DESC",
        }.get(sort, "created_at DESC")

        offset = max(page - 1, 0) * page_size

        with self.connection() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) AS count FROM scans {where_clause}",
                params,
            ).fetchone()["count"]
            rows = conn.execute(
                f"SELECT * FROM scans {where_clause} ORDER BY {order_by} LIMIT ? OFFSET ?",
                [*params, page_size, offset],
            ).fetchall()

        return {
            "page": page,
            "page_size": page_size,
            "total": total,
            "items": [self._row_to_scan_dict(row) for row in rows],
        }

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        """Return one scan row as a dictionary, or None if it does not exist."""
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if row is None:
                return None
            return self._row_to_scan_dict(row)

    def get_scan_findings(
        self,
        scan_id: str,
        *,
        severity: str | None = None,
        category: str | None = None,
        rule_family_filter: str | None = None,
        file_query: str | None = None,
        q: str | None = None,
        page: int = 1,
        page_size: int = 50,
        sort: str = "severity_desc",
    ) -> dict[str, Any] | None:
        """Return filtered normalized findings for a scan, or None if the scan does not exist."""
        with self.connection() as conn:
            scan_exists = conn.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if scan_exists is None:
                return None

            filters: list[str] = ["scan_id = ?"]
            params: list[Any] = [scan_id]
            if severity:
                filters.append("severity = ?")
                params.append(severity)
            if category:
                filters.append("category = ?")
                params.append(category)
            if file_query:
                filters.append("file LIKE ?")
                params.append(f"%{file_query}%")

            rows = conn.execute(
                f"""
                SELECT rule_id, payload_json
                FROM scan_findings
                WHERE {' AND '.join(filters)}
                """,
                params,
            ).fetchall()

        findings = [json.loads(row["payload_json"]) for row in rows]
        if rule_family_filter:
            findings = [
                finding
                for finding in findings
                if rule_family(str(finding.get("id") or "")) == rule_family_filter.upper()
            ]
        if q:
            q_lower = q.lower()
            findings = [
                finding
                for finding in findings
                if q_lower
                in " ".join(
                    [
                        str(finding.get("id") or ""),
                        str(finding.get("pattern") or ""),
                        str(finding.get("category") or ""),
                        str((finding.get("location") or {}).get("file") or ""),
                        str(finding.get("explanation") or ""),
                    ]
                ).lower()
            ]

        findings = self._sort_findings(findings, sort)
        total = len(findings)
        start = max(page - 1, 0) * page_size
        end = start + page_size
        paged = findings[start:end]

        return {
            "scan_id": scan_id,
            "status": scan_exists["status"],
            "total": total,
            "page": page,
            "page_size": page_size,
            "findings": paged,
        }

    def get_scan_events(self, scan_id: str) -> list[dict[str, Any]] | None:
        """Return event history for a scan, or None if the scan does not exist."""
        with self.connection() as conn:
            scan_exists = conn.execute("SELECT 1 FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if scan_exists is None:
                return None
            rows = conn.execute(
                """
                SELECT id, scan_id, status, message, created_at
                FROM scan_events
                WHERE scan_id = ?
                ORDER BY id ASC
                """,
                (scan_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_scan_report(self, scan_id: str, fmt: str) -> dict[str, str] | None:
        """Return one stored report, or None if the scan/report does not exist."""
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT content, content_type
                FROM scan_reports
                WHERE scan_id = ? AND format = ?
                """,
                (scan_id, fmt),
            ).fetchone()
            if row is None:
                return None
            return {
                "content": row["content"],
                "content_type": row["content_type"],
            }

    def claim_next_scan(self) -> dict[str, Any] | None:
        """Claim the next queued scan and mark it as running."""
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT id, target, mode, requested_formats
                FROM scans
                WHERE status = 'queued'
                ORDER BY created_at ASC
                LIMIT 1
                """
            ).fetchone()
            if row is None:
                return None

            started_at = utc_now_iso()
            updated = conn.execute(
                """
                UPDATE scans
                SET status = 'running', started_at = ?
                WHERE id = ? AND status = 'queued'
                """,
                (started_at, row["id"]),
            )
            if updated.rowcount != 1:
                return None

            self._record_event(conn, row["id"], "running", "Worker started deterministic scan.")
            claimed = conn.execute("SELECT * FROM scans WHERE id = ?", (row["id"],)).fetchone()
            return self._row_to_scan_dict(claimed) if claimed is not None else None

    def complete_scan(
        self,
        scan_id: str,
        *,
        summary: dict[str, Any],
        reports: dict[str, dict[str, str]],
        findings: list[dict[str, Any]],
    ) -> None:
        """Mark a scan complete and persist its reports and findings."""
        with self.connection() as conn:
            conn.execute("DELETE FROM scan_reports WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM scan_findings WHERE scan_id = ?", (scan_id,))

            for fmt, report in reports.items():
                conn.execute(
                    """
                    INSERT INTO scan_reports (scan_id, format, content, content_type)
                    VALUES (?, ?, ?, ?)
                    """,
                    (scan_id, fmt, report["content"], report["content_type"]),
                )

            for finding in findings:
                location = finding.get("location") or {}
                conn.execute(
                    """
                    INSERT INTO scan_findings (
                        scan_id, rule_id, category, pattern, severity, confidence,
                        file, start_line, end_line, payload_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        finding.get("id", "UNKNOWN"),
                        finding.get("category"),
                        finding.get("pattern"),
                        finding.get("severity", "LOW"),
                        float(finding.get("confidence", 0.0)),
                        location.get("file", "SKILL.md"),
                        int(location.get("start_line", 1)),
                        location.get("end_line"),
                        json.dumps(finding),
                    ),
                )

            conn.execute(
                """
                UPDATE scans
                SET status = 'completed',
                    completed_at = ?,
                    error = NULL,
                    risk_score = ?,
                    severity = ?,
                    recommendation = ?,
                    safe_to_install = ?,
                    findings_count = ?,
                    findings_by_severity = ?,
                    findings_by_category = ?,
                    available_reports = ?,
                    scanner_version = ?,
                    scan_mode = ?,
                    llm_requested = ?,
                    llm_used = ?,
                    agent_review_requested = ?,
                    agent_review_used = ?,
                    agent_review_status = ?,
                    agent_review_verdict = ?,
                    agent_review_summary = ?,
                    agent_review_json = ?
                WHERE id = ?
                """,
                (
                    utc_now_iso(),
                    summary.get("risk_score"),
                    summary.get("severity"),
                    summary.get("recommendation"),
                    1 if summary.get("safe_to_install") else 0,
                    summary.get("findings_count", 0),
                    json.dumps(summary.get("findings_by_severity", {})),
                    json.dumps(summary.get("findings_by_category", {})),
                    json.dumps(sorted(reports)),
                    summary.get("scanner_version"),
                    summary.get("scan_mode", "static-only"),
                    1 if summary.get("llm_requested") else 0,
                    1 if summary.get("llm_used") else 0,
                    1 if summary.get("agent_review_requested") else 0,
                    1 if summary.get("agent_review_used") else 0,
                    summary.get("agent_review_status"),
                    summary.get("agent_review_verdict"),
                    summary.get("agent_review_summary"),
                    json.dumps(summary.get("agent_review_report")) if summary.get("agent_review_report") is not None else None,
                    scan_id,
                ),
            )
            self._record_event(conn, scan_id, "completed", "Deterministic scan completed.")

    def fail_scan(self, scan_id: str, error: str) -> None:
        """Mark a scan as failed with an error message."""
        with self.connection() as conn:
            conn.execute(
                """
                UPDATE scans
                SET status = 'failed', completed_at = ?, error = ?
                WHERE id = ?
                """,
                (utc_now_iso(), error[:2000], scan_id),
            )
            self._record_event(conn, scan_id, "failed", f"Deterministic scan failed: {error[:500]}")

    def fail_running_scans(self, error: str) -> int:
        """Mark any in-flight scans as failed after an unclean shutdown/restart."""
        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT id
                FROM scans
                WHERE status = 'running'
                """
            ).fetchall()
            if not rows:
                return 0

            completed_at = utc_now_iso()
            conn.execute(
                """
                UPDATE scans
                SET status = 'failed', completed_at = ?, error = ?
                WHERE status = 'running'
                """,
                (completed_at, error[:2000]),
            )
            for row in rows:
                self._record_event(
                    conn,
                    row["id"],
                    "failed",
                    f"Deterministic scan failed: {error[:500]}",
                )
            return len(rows)

    def _record_event(
        self,
        conn: sqlite3.Connection,
        scan_id: str,
        status: str,
        message: str,
    ) -> None:
        """Insert one scan event row."""
        conn.execute(
            """
            INSERT INTO scan_events (scan_id, status, message, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (scan_id, status, message, utc_now_iso()),
        )

    def get_agent_review_report(self, scan_id: str) -> dict[str, Any] | None:
        """Return the stored bounded-agent review payload for a scan."""
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT agent_review_requested, agent_review_used, agent_review_status,
                       agent_review_verdict, agent_review_summary, agent_review_json
                FROM scans
                WHERE id = ?
                """,
                (scan_id,),
            ).fetchone()
            if row is None:
                return None
            return {
                "requested": bool(row["agent_review_requested"]),
                "used": bool(row["agent_review_used"]),
                "status": row["agent_review_status"],
                "verdict": row["agent_review_verdict"],
                "summary": row["agent_review_summary"],
                "report": self._loads_or_default(row["agent_review_json"], default=None),
            }

    def _row_to_scan_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        """Convert a scan row to a JSON-ready dictionary."""
        return {
            "scan_id": row["id"],
            "target": row["target"],
            "mode": row["mode"],
            "status": row["status"],
            "requested_formats": json.loads(row["requested_formats"]),
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
            "error": row["error"],
            "risk_score": row["risk_score"],
            "severity": row["severity"],
            "recommendation": row["recommendation"],
            "safe_to_install": bool(row["safe_to_install"]) if row["safe_to_install"] is not None else None,
            "findings_count": row["findings_count"],
            "findings_by_severity": self._loads_or_default(row["findings_by_severity"]),
            "findings_by_category": self._loads_or_default(row["findings_by_category"]),
            "available_reports": self._loads_or_default(row["available_reports"], default=[]),
            "scanner_version": row["scanner_version"],
            "scan_mode": row["scan_mode"],
            "llm_requested": bool(row["llm_requested"]),
            "llm_used": bool(row["llm_used"]),
            "agent_review_provider": row["agent_review_provider"],
            "agent_review_skill": row["agent_review_skill"],
            "agent_review_prompt": row["agent_review_prompt"],
            "agent_review_model": row["agent_review_model"],
            "agent_review_requested": bool(row["agent_review_requested"]),
            "agent_review_used": bool(row["agent_review_used"]),
            "agent_review_status": row["agent_review_status"],
            "agent_review_verdict": row["agent_review_verdict"],
            "agent_review_summary": row["agent_review_summary"],
            "agent_review_report": self._loads_or_default(row["agent_review_json"], default=None),
        }

    @staticmethod
    def _ensure_scan_column(conn: sqlite3.Connection, column_name: str, ddl: str) -> None:
        """Add one scans-table column if it is not present yet."""
        existing = {
            str(row["name"])
            for row in conn.execute("PRAGMA table_info(scans)").fetchall()
        }
        if column_name in existing:
            return
        conn.execute(f"ALTER TABLE scans ADD COLUMN {column_name} {ddl}")

    @staticmethod
    def _loads_or_default(raw: str | None, *, default: Any | None = None) -> Any:
        """Decode stored JSON, or return the provided default."""
        if raw in (None, ""):
            return {} if default is None else default
        return json.loads(raw)

    @staticmethod
    def _sort_findings(findings: list[dict[str, Any]], sort: str) -> list[dict[str, Any]]:
        """Sort findings for the frontend table."""
        if sort == "file_asc":
            return sorted(
                findings,
                key=lambda item: (
                    str((item.get("location") or {}).get("file") or ""),
                    int((item.get("location") or {}).get("start_line") or 0),
                    str(item.get("id") or ""),
                ),
            )
        if sort == "file_desc":
            return sorted(
                findings,
                key=lambda item: (
                    str((item.get("location") or {}).get("file") or ""),
                    int((item.get("location") or {}).get("start_line") or 0),
                    str(item.get("id") or ""),
                ),
                reverse=True,
            )
        if sort == "rule_id_asc":
            return sorted(findings, key=lambda item: str(item.get("id") or ""))
        if sort == "rule_id_desc":
            return sorted(findings, key=lambda item: str(item.get("id") or ""), reverse=True)
        return sorted(
            findings,
            key=lambda item: (
                SEVERITY_ORDER.get(str(item.get("severity") or "").upper(), 99),
                str((item.get("location") or {}).get("file") or ""),
                int((item.get("location") or {}).get("start_line") or 0),
                str(item.get("id") or ""),
            ),
        )
