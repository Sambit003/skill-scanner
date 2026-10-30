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
    scan_scope: Literal["skill_files", "skill_folders", "repository"]
    include_readme: bool
    # What set the recommendation; optional, stored on the scan row.
    verdict_reason: str | None = None


class ScannerReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str
    content_type: str


class ScannerCapabilityLocation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file: str
    start_line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)


class ScannerCapability(BaseModel):
    """Something the skill can do, listed apart from findings and not counted
    in the risk score. Present only when the scan request opted in."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    label: str
    location: ScannerCapabilityLocation
    snippet: str | None = None


class ScannerResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["scan"]
    summary: ScannerSummary
    findings: List[Dict[str, Any]]
    # The scanner omits the list when it is empty or was not requested.
    capabilities: List[ScannerCapability] | None = None
    reports: Dict[str, ScannerReport]


class ScannerFrameworkRefs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mapping_version: str
    owasp_agentic: List[str]
    owasp_llm: List[str]
    nist_gai_risks: List[str]
    nist_rmf: List[str]


class ScannerRuleDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    rule_family: str
    title: str
    category: str
    description: str
    remediation: str
    documentation_url: str
    frameworks: ScannerFrameworkRefs | None = None



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

    protocol_version: Literal["2"]
    ok: Literal[True]
    result: ScannerProtocolResult
