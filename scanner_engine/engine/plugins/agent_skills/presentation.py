"""Frontend-facing view helpers for scans, findings, reports, and rule docs."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from scanner_engine.engine.plugins.agent_skills.nodes.analyzers.pattern_defaults import (
    DEFAULT_EXPLANATIONS,
    DEFAULT_REMEDIATIONS,
    PATTERN_NAMES,
    RULE_ID_TO_CATEGORY,
)

EXTRA_RULE_DOCS: dict[str, dict[str, str]] = {
    "PE4": {
        "title": "Docker Socket Access",
        "category": "Privilege Escalation",
        "description": (
            "Access to the Docker socket gives effective root-equivalent control over the host "
            "through container management APIs."
        ),
        "remediation": (
            "Remove Docker socket access from the skill. If container management is required, "
            "proxy only the minimal safe operations through a tightly-scoped service."
        ),
    },
    "PE5": {
        "title": "Privileged Container / Container Escape",
        "category": "Privilege Escalation",
        "description": (
            "Privileged containers, host namespaces, host mounts, or dangerous capabilities "
            "can break isolation and lead to host compromise."
        ),
        "remediation": (
            "Drop privileged mode, host namespace flags, and dangerous capabilities. Use a "
            "least-privilege security context and avoid mounting host resources."
        ),
    },
    "RP1": {
        "title": "Unpinned External Reference",
        "category": "MCP Rug Pull",
        "description": (
            "The skill references an external MCP server, package, or image without version pinning, "
            "creating a supply-chain rug-pull risk."
        ),
        "remediation": "Pin the exact package, image tag, or digest used by the skill.",
    },
    "RP2": {
        "title": "Manifest Expansion Risk",
        "category": "MCP Rug Pull",
        "description": (
            "The manifest suggests future permission or trigger expansion that could materially "
            "change behavior in later versions."
        ),
        "remediation": (
            "Audit manifest changes carefully and pin to reviewed versions before accepting updates."
        ),
    },
    "RP3": {
        "title": "Unpinned Skill Version",
        "category": "MCP Rug Pull",
        "description": (
            "The skill version or parameter schema is too broad or changed in a way that increases "
            "upgrade risk."
        ),
        "remediation": "Pin to a reviewed version and verify schema/default changes before upgrade.",
    },
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def rule_family(rule_id: str) -> str:
    """Extract the alphabetic family prefix from a rule id."""
    prefix_chars: list[str] = []
    for char in (rule_id or "").strip().upper():
        if char.isalpha() or (char == "-" and prefix_chars):
            if char != "-":
                prefix_chars.append(char)
            continue
        break
    return "".join(prefix_chars) or "GEN"


def rule_doc_url(rule_id: str) -> str:
    """Return the API-local documentation URL for a rule id."""
    return f"/v1/rules/{rule_id}"


def get_rule_doc(rule_id: str) -> dict[str, str]:
    """Return a frontend-friendly rule documentation object."""
    if rule_id in EXTRA_RULE_DOCS:
        extra = EXTRA_RULE_DOCS[rule_id]
        return {
            "rule_id": rule_id,
            "rule_family": rule_family(rule_id),
            "title": extra["title"],
            "category": extra["category"],
            "description": extra["description"],
            "remediation": extra["remediation"],
            "documentation_url": rule_doc_url(rule_id),
        }

    return {
        "rule_id": rule_id,
        "rule_family": rule_family(rule_id),
        "title": PATTERN_NAMES.get(rule_id, rule_id),
        "category": RULE_ID_TO_CATEGORY.get(rule_id, "Security"),
        "description": DEFAULT_EXPLANATIONS.get(
            rule_id, "Potential security issue detected. Manual review is recommended."
        ),
        "remediation": DEFAULT_REMEDIATIONS.get(
            rule_id,
            "Review the finding and remove unsafe behavior or broadened permissions.",
        ),
        "documentation_url": rule_doc_url(rule_id),
    }


def all_rule_docs() -> list[dict[str, str]]:
    """Return the full rule registry in a stable order."""
    all_rule_ids = sorted(set(PATTERN_NAMES) | set(DEFAULT_EXPLANATIONS) | set(EXTRA_RULE_DOCS))
    return [get_rule_doc(rule_id) for rule_id in all_rule_ids]


def enrich_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Augment one normalized finding with frontend-facing fields."""
    location = finding.get("location") or {}
    file_path = str(location.get("file") or "SKILL.md")
    start_line = location.get("start_line")
    rule_id = str(finding.get("id") or "UNKNOWN")
    rule_doc = get_rule_doc(rule_id)
    pattern = finding.get("pattern") or rule_doc["title"]

    return {
        **finding,
        "title": pattern,
        "rule_family": rule_doc["rule_family"],
        "documentation_url": rule_doc["documentation_url"],
        "file_path_display": f"{file_path}:{start_line}" if start_line else file_path,
    }


def _parse_iso8601(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def compute_duration(started_at: str | None, completed_at: str | None) -> tuple[int | None, float | None]:
    """Return duration in whole seconds and milliseconds if both timestamps exist."""
    started = _parse_iso8601(started_at)
    completed = _parse_iso8601(completed_at)
    if started is None or completed is None:
        return None, None
    delta_ms = max(0.0, (completed - started).total_seconds() * 1000)
    return int(round(delta_ms / 1000)), delta_ms


def primary_verdict(scan: dict[str, Any]) -> str | None:
    """Return frontend-friendly verdict label."""
    recommendation = str(scan.get("recommendation") or "").upper()
    if recommendation == "DO_NOT_INSTALL":
        return "unsafe"
    if recommendation == "CAUTION":
        return "caution"
    if recommendation == "SAFE":
        return "safe"
    return None


def headline(scan: dict[str, Any]) -> str | None:
    """Return hero-card headline text."""
    verdict = primary_verdict(scan)
    return {
        "unsafe": "Unsafe to Install",
        "caution": "Needs Review",
        "safe": "Safe to Install",
    }.get(verdict)


def summary_text(scan: dict[str, Any]) -> str | None:
    """Return a short UI summary line for the scan result."""
    verdict = primary_verdict(scan)
    findings_count = scan.get("findings_count") or 0
    severity = scan.get("severity") or "UNKNOWN"
    if verdict == "unsafe":
        return (
            f"This scan detected {severity.lower()}-risk patterns across {findings_count} finding(s). "
            "Remediation is required before deployment."
        )
    if verdict == "caution":
        return (
            f"This scan detected moderate-risk patterns across {findings_count} finding(s). "
            "Manual review is recommended before deployment."
        )
    if verdict == "safe":
        return (
            f"This scan found no blocking issues and reported {findings_count} finding(s). "
            "The repository appears safe for deterministic install review."
        )
    return None


def display_target(target: str) -> str:
    """Return a compact target label suitable for cards."""
    if len(target) <= 48:
        return target
    return f"{target[:45]}..."


def breakdown_items(counts: dict[str, int], *, sort_by_count: bool = False) -> list[dict[str, Any]]:
    """Convert a dict breakdown to a stable array for charts."""
    items = [{"label": label, "count": count} for label, count in counts.items()]
    if sort_by_count:
        return sorted(items, key=lambda item: (-item["count"], item["label"]))
    return sorted(
        items,
        key=lambda item: (SEVERITY_ORDER.get(str(item["label"]).upper(), 99), item["label"]),
    )


def report_downloads(scan_id: str, formats: list[str]) -> list[dict[str, str]]:
    """Return explicit report download links."""
    return [
        {
            "format": fmt,
            "url": f"/v1/scans/{scan_id}/reports/{fmt}",
        }
        for fmt in formats
    ]


def scan_links(scan_id: str) -> dict[str, str]:
    """Return canonical related-resource links for one scan."""
    return {
        "self": f"/v1/scans/{scan_id}",
        "findings": f"/v1/scans/{scan_id}/findings",
        "reports": f"/v1/scans/{scan_id}/reports",
        "events": f"/v1/scans/{scan_id}/events",
        "share_summary": f"/v1/scans/{scan_id}/share-summary",
    }


def enrich_scan(scan: dict[str, Any], *, default_poll_after_ms: int = 2000) -> dict[str, Any]:
    """Augment one scan summary row with frontend-facing convenience fields."""
    duration_seconds, duration_ms = compute_duration(scan.get("started_at"), scan.get("completed_at"))
    available_reports = list(scan.get("available_reports") or [])
    is_terminal = scan.get("status") in {"completed", "failed", "canceled"}
    scan_id = str(scan.get("scan_id") or "")

    return {
        **scan,
        "duration_seconds": duration_seconds,
        "duration_ms": duration_ms,
        "display_target": display_target(str(scan.get("target") or "")),
        "primary_verdict": primary_verdict(scan),
        "headline": headline(scan),
        "summary": summary_text(scan),
        "severity_breakdown": breakdown_items(scan.get("findings_by_severity") or {}),
        "category_breakdown": breakdown_items(
            scan.get("findings_by_category") or {}, sort_by_count=True
        ),
        "report_downloads": report_downloads(scan_id, available_reports),
        "is_terminal": is_terminal,
        "next_poll_after_ms": 0 if is_terminal else default_poll_after_ms,
        "links": scan_links(scan_id),
    }
