"""Versioned process contract shared by the Python and future Go scanner engines."""

from __future__ import annotations

from dataclasses import asdict
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from scan_kernel.engine import ReportFormat, ScanConfig, ScanEngine, ScanResult

PROTOCOL_VERSION = "1"


class ScanRequest(BaseModel):
    """One JSON request read from stdin by the machine-facing engine process."""

    model_config = ConfigDict(extra="forbid")

    operation: Literal["scan"]
    protocol_version: Literal["1"]
    target: str = Field(min_length=1)
    asset_type: str = Field(min_length=1)
    output_formats: list[ReportFormat] = Field(min_length=1)
    timeout_seconds: float = Field(gt=0, le=3600)


class ListRulesRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation: Literal["list_rules"]
    protocol_version: Literal["1"]


class GetRuleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation: Literal["get_rule"]
    protocol_version: Literal["1"]
    rule_id: str = Field(min_length=1)


EngineRequest = Annotated[
    ScanRequest | ListRulesRequest | GetRuleRequest,
    Field(discriminator="operation"),
]


def _normalize_finding(raw: dict[str, Any]) -> dict[str, Any]:
    location = raw.get("location") if isinstance(raw.get("location"), dict) else {}
    return {
        **raw,
        "id": str(raw.get("id") or "UNKNOWN"),
        "category": str(raw.get("category") or "Security"),
        "severity": str(raw.get("severity") or "UNKNOWN"),
        "confidence": float(raw.get("confidence") or 0.0),
        "location": {
            "file": str(location.get("file") or ""),
            "start_line": int(location.get("start_line") or 1),
            "end_line": location.get("end_line"),
        },
    }


def success_envelope(result: ScanResult) -> dict[str, Any]:
    """Serialize the internal engine result without exposing Python-only state."""

    return {
        "protocol_version": PROTOCOL_VERSION,
        "ok": True,
        "result": {
            "kind": "scan",
            "summary": asdict(result.summary),
            "findings": [_normalize_finding(finding) for finding in result.findings],
            "reports": {
                report_format.value: {
                    "content": report.content,
                    "content_type": report.content_type,
                }
                for report_format, report in result.reports.items()
            },
        },
    }


def error_envelope(code: str, message: str) -> dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "ok": False,
        "error": {"code": code, "message": message},
    }


async def execute_request(request: ScanRequest) -> dict[str, Any]:
    result = await ScanEngine.execute_async(
        ScanConfig(
            target=request.target,
            asset_type=request.asset_type,
            output_formats=request.output_formats,
            timeout_seconds=request.timeout_seconds,
        )
    )
    return success_envelope(result)


def execute_metadata_request(request: ListRulesRequest | GetRuleRequest) -> dict[str, Any]:
    from scan_kernel.engine.plugins.agent_skills.presentation import all_rule_docs, get_rule_doc

    if isinstance(request, ListRulesRequest):
        result: dict[str, Any] = {"kind": "rules", "items": all_rule_docs()}
    else:
        result = {"kind": "rule", "rule": get_rule_doc(request.rule_id)}

    return {"protocol_version": PROTOCOL_VERSION, "ok": True, "result": result}
