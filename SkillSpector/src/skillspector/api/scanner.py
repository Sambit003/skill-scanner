"""Deterministic scan runner for API jobs."""

from __future__ import annotations

from copy import copy
from typing import Any

from skillspector import __version__
from skillspector.cleanup import cleanup_result
from skillspector.constants import RISK_THRESHOLD
from skillspector.graph import graph
from skillspector.nodes.report import report

CONTENT_TYPES = {
    "json": "application/json",
    "markdown": "text/markdown; charset=utf-8",
    "sarif": "application/sarif+json",
    "terminal": "text/plain; charset=utf-8",
}


def _count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    """Count findings by one top-level key."""
    counts: dict[str, int] = {}
    for item in items:
        label = str(item.get(key) or "UNKNOWN")
        counts[label] = counts.get(label, 0) + 1
    return counts


async def run_deterministic_scan(
    target: str,
    requested_formats: list[str],
    *,
    agent_review_enabled: bool = False,
    agent_review_provider: str | None = None,
    agent_review_skill: str | None = None,
    agent_review_prompt: str | None = None,
    agent_review_model: str | None = None,
    agent_review_api_key: str | None = None,
) -> tuple[dict[str, Any], dict[str, dict[str, str]], list[dict[str, Any]]]:
    """Run the deterministic graph once, then render each requested report format."""
    reports: dict[str, dict[str, str]] = {}
    requested_unique_formats = list(dict.fromkeys(requested_formats))
    canonical_format = "json" if "json" in requested_unique_formats else requested_unique_formats[0]
    formats_to_render = list(dict.fromkeys([*requested_unique_formats, "json"]))

    result: dict[str, Any] | None = None
    try:
        result = await graph.ainvoke(
            {
                "input_path": target,
                "output_format": canonical_format,
                "use_llm": False,
                "agent_review_enabled": agent_review_enabled,
                "agent_review_provider": agent_review_provider,
                "agent_review_skill": agent_review_skill,
                "agent_review_prompt": agent_review_prompt,
                "agent_review_model": agent_review_model,
                "agent_review_api_key": agent_review_api_key,
            },
            config={
                "run_name": f"skillspector-api-{canonical_format}",
                "tags": ["skillspector", "api", "deterministic"],
                "metadata": {
                    "input_path": target,
                    "use_llm": False,
                    "output_format": canonical_format,
                    "version": __version__,
                },
            },
        )

        findings = result.get("filtered_findings") or result.get("findings") or []
        normalized_findings = [finding.to_dict() for finding in findings]
        summary = {
            "risk_score": int(result.get("risk_score") or 0),
            "severity": result.get("risk_severity"),
            "recommendation": result.get("risk_recommendation"),
            "safe_to_install": int(result.get("risk_score") or 0) <= RISK_THRESHOLD,
            "findings_count": len(normalized_findings),
            "findings_by_severity": _count_by(normalized_findings, "severity"),
            "findings_by_category": _count_by(normalized_findings, "category"),
            "scanner_version": __version__,
            "scan_mode": "static-only",
            "llm_requested": False,
            "llm_used": False,
            "agent_review_provider": result.get("agent_review_provider") or agent_review_provider,
            "agent_review_requested": bool(result.get("agent_review_requested") or agent_review_enabled),
            "agent_review_used": bool(result.get("agent_review_used")),
            "agent_review_status": result.get("agent_review_status"),
            "agent_review_verdict": result.get("agent_review_verdict"),
            "agent_review_summary": result.get("agent_review_summary"),
            "agent_review_report": result.get("agent_review_report"),
        }

        for fmt in formats_to_render:
            if fmt == canonical_format:
                report_body = result.get("report_body") or ""
            else:
                rendered = report(
                    {
                        **copy(result),
                        "output_format": fmt,
                        "use_llm": False,
                    }
                )
                report_body = rendered.get("report_body") or ""

            reports[fmt] = {
                "content": report_body,
                "content_type": CONTENT_TYPES[fmt],
            }
    finally:
        if result is not None:
            cleanup_result(result)

    if summary is None:
        raise RuntimeError("deterministic scan produced no summary")

    return summary, reports, normalized_findings
