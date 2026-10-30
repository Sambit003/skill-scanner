import re
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator

ScanScope = Literal["skill_files", "skill_folders", "repository"]

class ScanCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(..., description="Target file path, git URL, or directory to scan")
    asset_type: str = Field(default="agent_skill", description="Type of asset (e.g. agent_skill, mcp_server)")
    tags: List[str] = Field(default_factory=list)
    scan_scope: ScanScope = "skill_folders"
    include_readme: bool = False

    @model_validator(mode="after")
    def validate_readme_scope(self) -> "ScanCreateRequest":
        if self.scan_scope == "skill_files" and self.include_readme:
            raise ValueError("include_readme is not applicable to skill_files scope")
        return self

class FrameworkRefs(BaseModel):
    mapping_version: str
    owasp_agentic: List[str] = Field(default_factory=list)
    owasp_llm: List[str] = Field(default_factory=list)
    nist_gai_risks: List[str] = Field(default_factory=list)
    nist_rmf: List[str] = Field(default_factory=list)

class FindingLocation(BaseModel):
    file: str
    start_line: int
    end_line: Optional[int] = None

class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    rule_id: str
    title: str
    severity: str
    category: str
    rule_family: Optional[str] = None
    pattern: Optional[str] = None
    confidence: float = 0.8
    location: Optional[FindingLocation] = None
    file_path_display: Optional[str] = None
    finding: Optional[str] = None
    description: Optional[str] = None
    explanation: Optional[str] = None
    remediation: Optional[str] = None
    file_path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    code_snippet: Optional[str] = None
    intent: Optional[str] = None
    documentation_url: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    frameworks: Optional[FrameworkRefs] = None
    extra_metadata: Optional[Dict[str, Any]] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.location:
            self.location = FindingLocation(
                file=self.file_path or "unknown",
                start_line=self.start_line or 1,
                end_line=self.end_line,
            )
        if not self.file_path_display:
            self.file_path_display = self.file_path
            if self.file_path_display and self.start_line:
                self.file_path_display = f"{self.file_path_display}:{self.start_line}"
        if not self.explanation and self.description:
            self.explanation = self.description
        if self.extra_metadata and isinstance(self.extra_metadata, dict):
            metadata_confidence = self.extra_metadata.get("confidence")
            if isinstance(metadata_confidence, (int, float)):
                self.confidence = float(metadata_confidence)
            if not self.rule_family and self.extra_metadata.get("rule_family"):
                self.rule_family = str(self.extra_metadata.get("rule_family"))
            if not self.pattern and self.extra_metadata.get("pattern"):
                self.pattern = self.extra_metadata.get("pattern")
            if not self.tags and self.extra_metadata.get("tags"):
                self.tags = self.extra_metadata.get("tags")
            if not self.explanation and self.extra_metadata.get("explanation"):
                self.explanation = self.extra_metadata.get("explanation")
            if not self.code_snippet and self.extra_metadata.get("code_snippet"):
                self.code_snippet = self.extra_metadata.get("code_snippet")
            if not self.finding and self.extra_metadata.get("finding"):
                self.finding = self.extra_metadata.get("finding")
            if not self.frameworks and self.extra_metadata.get("frameworks"):
                metadata_frameworks = self.extra_metadata.get("frameworks")
                if isinstance(metadata_frameworks, dict):
                    try:
                        self.frameworks = FrameworkRefs(**metadata_frameworks)
                    except Exception:
                        self.frameworks = None
        if not self.rule_family:
            match = re.match(r"[A-Za-z]+", self.rule_id or "")
            self.rule_family = match.group(0).upper() if match else None
        if not self.finding:
            self.finding = self.title
        if not self.documentation_url and self.rule_id:
            self.documentation_url = f"/v1/rules/{self.rule_id}"

class CapabilityResponse(BaseModel):
    """Something the skill can do, not a problem and not counted in the risk score."""

    rule_id: str
    label: str
    location: FindingLocation
    snippet: Optional[str] = None
    documentation_url: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if not self.documentation_url and self.rule_id:
            self.documentation_url = f"/v1/rules/{self.rule_id}"

class ScanFindingsResponse(BaseModel):
    scan_id: str
    status: str
    total: int
    page: int = 1
    page_size: int = 500
    findings: List[FindingResponse] = Field(default_factory=list)

class ScanSummaryResponse(BaseModel):
    risk_score: Optional[int] = None
    severity: Optional[str] = None
    recommendation: Optional[str] = None
    safe_to_install: Optional[bool] = None
    findings_count: int = 0
    findings_by_severity: Dict[str, int] = Field(default_factory=dict)
    findings_by_category: Dict[str, int] = Field(default_factory=dict)

class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: Optional[str] = None
    asset_target: str
    repository_key: str
    target: Optional[str] = None
    asset_type: str = "agent_skill"
    status: str
    current_stage: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    error: Optional[str] = None
    mode: str = "deterministic"
    scan_scope: ScanScope = "skill_folders"
    include_readme: bool = False

    def model_post_init(self, __context: Any) -> None:
        if not self.scan_id:
            self.scan_id = self.id
        if not self.target:
            self.target = self.asset_target
        if not self.error and self.error_message:
            self.error = self.error_message
        if self.status:
            self.status = self.status.lower()

class ScanListItemResponse(ScanResponse):
    display_target: Optional[str] = None
    duration_seconds: Optional[float] = None
    is_terminal: bool = False
    risk_score: Optional[int] = None
    severity: Optional[str] = None
    recommendation: Optional[str] = None
    safe_to_install: Optional[bool] = None
    headline: Optional[str] = None
    summary: Optional[str] = None
    findings_count: int = 0

class BreakdownItem(BaseModel):
    label: str
    count: int

class ScanLinksResponse(BaseModel):
    self: str
    findings: str
    reports: str
    events: str
    share_summary: str

class ReportLinkItem(BaseModel):
    format: str
    url: str

class ScanDetailResponse(ScanResponse):
    display_target: Optional[str] = None
    requested_formats: List[str] = Field(default_factory=lambda: ["json", "markdown", "sarif", "terminal"])
    duration_seconds: Optional[float] = None
    duration_ms: Optional[float] = None
    is_terminal: bool = False
    next_poll_after_ms: int = 2000
    risk_score: Optional[int] = None
    severity: Optional[str] = None
    recommendation: Optional[str] = None
    safe_to_install: Optional[bool] = None
    primary_verdict: Optional[str] = None
    headline: Optional[str] = None
    summary: Optional[str] = None
    findings_count: int = 0
    findings_by_severity: Dict[str, int] = Field(default_factory=dict)
    findings_by_category: Dict[str, int] = Field(default_factory=dict)
    severity_breakdown: List[BreakdownItem] = Field(default_factory=list)
    category_breakdown: List[BreakdownItem] = Field(default_factory=list)
    available_reports: List[str] = Field(default_factory=list)
    report_downloads: List[ReportLinkItem] = Field(default_factory=list)
    links: Optional[ScanLinksResponse] = None
    scanner_version: Optional[str] = "1.0.0"
    scan_mode: Optional[str] = "deterministic"
    findings: List[FindingResponse] = Field(default_factory=list)
    # None for scans recorded before the scanner listed capabilities.
    capabilities: Optional[List[CapabilityResponse]] = None
    # What set the recommendation; None for scans recorded before the scanner
    # gave a reason. The risk number is left out while scores are hidden.
    verdict_reason: Optional[str] = None
