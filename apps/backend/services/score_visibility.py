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
_NUMERIC_SCORE_FIELDS = ("risk_score", "vulnerability_score", "exposure_score")
# A verdict reason set by the additive score names the number:
# "CAUTION: risk 34 from 2 evidence findings".
_VERDICT_REASON_RISK_RE = re.compile(r"\brisk\s+\d+\s+from\s+")
_REPORT_VERDICT_REASON_RE = re.compile(r"^((?:\*\*)?Verdict reason:(?:\*\*)?\s.*)$", flags=re.MULTILINE)


def risk_scores_visible() -> bool:
    return bool(settings.SHOW_RISK_SCORES)


def visible_risk_score(score: Optional[int]) -> Optional[int]:
    return score if risk_scores_visible() else None


def visible_verdict_reason(reason: Optional[str]) -> Optional[str]:
    if not reason or risk_scores_visible():
        return reason
    return _VERDICT_REASON_RISK_RE.sub("", reason)


def _redact_report_verdict_reason(content: str) -> str:
    return _REPORT_VERDICT_REASON_RE.sub(lambda match: _VERDICT_REASON_RISK_RE.sub("", match.group(1)), content)


def redact_report_content(content: str, report_format: str) -> str:
    if risk_scores_visible():
        return content

    fmt = report_format.lower()
    if fmt == "json":
        return _redact_json_report(content)
    if fmt == "markdown":
        return _redact_report_verdict_reason(_MARKDOWN_RISK_RE.sub(r"**Severity:** \1  \n", content))
    if fmt == "terminal":
        return _redact_report_verdict_reason(_TERMINAL_RISK_RE.sub(r"ScanKernel: \1 — \2", content))
    return content


def _redact_json_report(content: str) -> str:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return content

    if isinstance(payload, dict):
        for field in _NUMERIC_SCORE_FIELDS:
            if field in payload:
                payload[field] = None
        summary = payload.get("summary")
        if isinstance(summary, dict):
            for field in _NUMERIC_SCORE_FIELDS:
                if field in summary:
                    summary[field] = None
            if isinstance(summary.get("verdict_reason"), str):
                summary["verdict_reason"] = visible_verdict_reason(summary["verdict_reason"])

    return json.dumps(payload, indent=2)
