"""Typed state shared by the deterministic ScanKernel pipeline."""

from __future__ import annotations

from typing import TypedDict

from scan_kernel.engine.plugins.agent_skills.models import Finding


class ScanKernelState(TypedDict, total=False):
    input_path: str | None
    skill_path: str | None
    temp_dir_for_cleanup: str | None
    zip_bytes: bytes | None
    mode: str

    components: list[str]
    file_cache: dict[str, str]
    ast_cache: dict[str, str]
    manifest: dict[str, object]
    previous_manifest: dict[str, object] | None
    component_metadata: list[dict[str, object]]
    has_executable_scripts: bool

    findings: list[Finding]
    filtered_findings: list[Finding]

    baseline: object | None
    show_suppressed: bool
    suppressed_findings: list[object]

    output_format: str
    report_body: str
    risk_severity: str
    risk_recommendation: str
    sarif_report: dict[str, object]
    risk_score: int
    yara_rules_dir: str | None


class AnalyzerNodeResponse(TypedDict):
    findings: list[Finding]


class FilterFindingsResponse(TypedDict):
    filtered_findings: list[Finding]
