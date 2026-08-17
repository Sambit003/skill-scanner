"""Customer-facing score visibility helpers.

ScanKernel still computes and persists numeric risk scores internally. This
module controls whether those scores are exposed through presentation-facing API
and report surfaces.
"""

from __future__ import annotations

import json
import re
from typing import Optional

from backend.core.config import settings


_MARKDOWN_RISK_RE = re.compile(
    r"^\*\*Risk:\*\*\s*\d+\s*/\s*100\s*\(([^)]+)\)\s*  \n",
    flags=re.MULTILINE,
)
_TERMINAL_RISK_RE = re.compile(
    r"^ScanKernel:\s*risk\s+\d+\s*/\s*100\s+([A-Z_]+)\s+—\s+(.+)$",
    flags=re.MULTILINE,
)


def risk_scores_visible() -> bool:
    return bool(settings.SHOW_RISK_SCORES)


def visible_risk_score(score: Optional[int]) -> Optional[int]:
    return score if risk_scores_visible() else None


def redact_report_content(content: str, report_format: str) -> str:
    if risk_scores_visible():
        return content

    fmt = report_format.lower()
    if fmt == "json":
        return _redact_json_report(content)
    if fmt == "markdown":
        return _MARKDOWN_RISK_RE.sub(r"**Severity:** \1  \n", content)
    if fmt == "terminal":
        return _TERMINAL_RISK_RE.sub(r"ScanKernel: \1 — \2", content)
    return content


def _redact_json_report(content: str) -> str:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return content

    if isinstance(payload, dict):
        if "risk_score" in payload:
            payload["risk_score"] = None
        summary = payload.get("summary")
        if isinstance(summary, dict) and "risk_score" in summary:
            summary["risk_score"] = None

    return json.dumps(payload, indent=2)
