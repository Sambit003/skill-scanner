"""Validated backend view of the language-neutral scanner process contract."""

from typing import Annotated, Any, Dict, List, Literal

from pydantic import BaseModel, ConfigDict, Field


class ScannerSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_score: int = Field(ge=0, le=100)
    vulnerability_score: int | None = Field(default=None, ge=0, le=100)
    exposure_score: float | None = Field(default=None, ge=0, le=100)
    severity: str
    recommendation: str
    safe_to_install: bool
    findings_count: int = Field(ge=0)
    findings_by_severity: Dict[str, int]
    findings_by_category: Dict[str, int]
    scanner_version: str
    scan_mode: str


class ScannerReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str
    content_type: str


class ScannerResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["scan"]
    summary: ScannerSummary
    findings: List[Dict[str, Any]]
    reports: Dict[str, ScannerReport]


class ScannerRuleDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    rule_family: str
    title: str
    category: str
    description: str
    remediation: str
    documentation_url: str


class ScannerRulesResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["rules"]
    items: List[ScannerRuleDoc]


class ScannerRuleResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["rule"]
    rule: ScannerRuleDoc


ScannerProtocolResult = Annotated[
    ScannerResult | ScannerRulesResult | ScannerRuleResult,
    Field(discriminator="kind"),
]


class ScannerSuccessEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol_version: Literal["1"]
    ok: Literal[True]
    result: ScannerProtocolResult
