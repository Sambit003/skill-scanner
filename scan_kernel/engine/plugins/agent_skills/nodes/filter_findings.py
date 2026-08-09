"""Deterministic post-processing for analyzer findings."""

from __future__ import annotations

from dataclasses import replace

from scan_kernel.engine.plugins.agent_skills.logging_config import get_logger
from scan_kernel.engine.plugins.agent_skills.models import Finding
from scan_kernel.engine.plugins.agent_skills.nodes.analyzers.common import is_code_example
from scan_kernel.engine.plugins.agent_skills.nodes.analyzers.pattern_defaults import (
    get_remediation,
)
from scan_kernel.engine.plugins.agent_skills.state import (
    FilterFindingsResponse,
    ScanKernelState,
)

logger = get_logger(__name__)

_CONFIDENCE_THRESHOLD = 0.4
_HIGH_SEVERITY_PASS_THROUGH = frozenset({"CRITICAL", "HIGH"})
_CODE_EXAMPLE_DOWNWEIGHT = 0.5


def filter_findings(state: ScanKernelState) -> FilterFindingsResponse:
    """Apply stable confidence filtering and default remediations."""
    findings = state.get("findings") or []
    filtered: list[Finding] = []

    for finding in findings:
        confidence = finding.confidence
        if finding.context and is_code_example(finding.context):
            confidence *= _CODE_EXAMPLE_DOWNWEIGHT

        severity = (finding.severity or "LOW").upper()
        if confidence < _CONFIDENCE_THRESHOLD and severity not in _HIGH_SEVERITY_PASS_THROUGH:
            continue

        filtered.append(
            replace(
                finding,
                confidence=confidence,
                remediation=finding.remediation or get_remediation(finding.rule_id),
                code_snippet=finding.code_snippet or finding.context,
                intent=None,
            )
        )

    logger.info("Deterministic finding filter: %d -> %d findings", len(findings), len(filtered))
    return {"filtered_findings": filtered}
