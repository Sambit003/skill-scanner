"""Pydantic schemas for the SkillSpector API service."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Response body for the health endpoint."""

    status: str = Field(description="Health status string.")
    service: str = Field(description="Service name.")
    scanner_version: str = Field(description="Installed SkillSpector version.")
    data_dir: str = Field(description="Persistent data directory path.")
    work_dir: str = Field(description="Temporary scan workspace path.")


class VersionResponse(BaseModel):
    """Response body for the version endpoint."""

    service: str = Field(description="Service name.")
    scanner_version: str = Field(description="Installed SkillSpector version.")


ReportFormat = Literal["json", "markdown", "sarif", "terminal"]
ScanMode = Literal["deterministic"]
ScanStatus = Literal["queued", "running", "completed", "failed", "canceled"]


class CreateScanRequest(BaseModel):
    """Request body for creating a scan job."""

    target: str = Field(description="Git URL, file URL, zip, file, or local directory.")
    mode: ScanMode = Field(default="deterministic", description="Requested scan mode.")
    formats: list[ReportFormat] = Field(
        default_factory=lambda: ["json"],
        description="Report formats to generate for the job.",
        min_length=1,
    )
    agent_review_enabled: bool = Field(
        default=False,
        description="Whether to run an optional post-scan agent review over deterministic findings.",
    )
    agent_review_skill: str | None = Field(
        default=None,
        description="Named internal review skill prompt to load for the bounded reviewer.",
    )
    agent_review_prompt: str | None = Field(
        default=None,
        description="Optional analyst instruction appended to the bounded review prompt.",
    )
    agent_review_model: str | None = Field(
        default=None,
        description="Optional model override for the bounded reviewer.",
    )
    agent_review_provider: Literal["openrouter"] | None = Field(
        default=None,
        description="Optional external provider used for BYOK bounded review.",
    )
    agent_review_api_key: str | None = Field(
        default=None,
        description="Optional BYOK API key used only for the current scan and never persisted.",
        exclude=True,
    )


class CreateScanResponse(BaseModel):
    """Response body for a created scan job."""

    scan_id: str = Field(description="Unique scan identifier.")
    status: ScanStatus = Field(description="Current scan status.")
    mode: ScanMode = Field(description="Accepted scan mode.")
    created_at: str = Field(description="Job creation timestamp.")
    agent_review_enabled: bool = Field(
        default=False,
        description="Whether bounded agent review was requested for this job.",
    )
    agent_review_provider: str | None = Field(
        default=None,
        description="External provider selected for bounded agent review, if any.",
    )


class BreakdownItemResponse(BaseModel):
    """Chart-friendly key/count response."""

    label: str
    count: int


class ReportLinkResponse(BaseModel):
    """Single downloadable report reference."""

    format: ReportFormat
    url: str


class ScanLinksResponse(BaseModel):
    """Related resource links for one scan."""

    self: str
    findings: str
    reports: str
    events: str
    share_summary: str


class ScanSummaryResponse(BaseModel):
    """Frontend-ready response body for one scan job."""

    scan_id: str
    target: str
    display_target: str | None = None
    mode: ScanMode
    status: ScanStatus
    requested_formats: list[ReportFormat]
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: int | None = None
    duration_ms: float | None = None
    is_terminal: bool = False
    next_poll_after_ms: int = 0
    error: str | None = None
    risk_score: int | None = None
    severity: str | None = None
    recommendation: str | None = None
    safe_to_install: bool | None = None
    primary_verdict: str | None = None
    headline: str | None = None
    summary: str | None = None
    findings_count: int | None = None
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    findings_by_category: dict[str, int] = Field(default_factory=dict)
    severity_breakdown: list[BreakdownItemResponse] = Field(default_factory=list)
    category_breakdown: list[BreakdownItemResponse] = Field(default_factory=list)
    available_reports: list[ReportFormat] = Field(default_factory=list)
    report_downloads: list[ReportLinkResponse] = Field(default_factory=list)
    links: ScanLinksResponse | None = None
    scanner_version: str | None = None
    scan_mode: str | None = None
    llm_requested: bool = False
    llm_used: bool = False
    agent_review_provider: str | None = None
    agent_review_model: str | None = None
    agent_review_requested: bool = False
    agent_review_used: bool = False
    agent_review_status: str | None = None
    agent_review_verdict: str | None = None
    agent_review_summary: str | None = None


class ScanListResponse(BaseModel):
    """Paginated scan-list response."""

    page: int
    page_size: int
    total: int
    items: list[ScanSummaryResponse] = Field(default_factory=list)


class FindingLocationResponse(BaseModel):
    """Normalized source location for a finding."""

    file: str
    start_line: int
    end_line: int | None = None


class FindingResponse(BaseModel):
    """Normalized finding payload exposed to the frontend."""

    id: str
    title: str | None = None
    rule_family: str | None = None
    category: str | None = None
    pattern: str | None = None
    severity: str
    confidence: float
    location: FindingLocationResponse
    file_path_display: str | None = None
    finding: str | None = None
    explanation: str | None = None
    remediation: str | None = None
    code_snippet: str | None = None
    intent: str | None = None
    documentation_url: str | None = None
    tags: list[str] = Field(default_factory=list)


class ScanFindingsResponse(BaseModel):
    """Response body for normalized findings of a completed scan."""

    scan_id: str
    status: ScanStatus
    total: int
    page: int = 1
    page_size: int = 50
    findings: list[FindingResponse] = Field(default_factory=list)


class ScanReportsManifestResponse(BaseModel):
    """Available report formats for a scan."""

    scan_id: str
    reports: list[ReportLinkResponse] = Field(default_factory=list)


class ScanEventResponse(BaseModel):
    """One scan lifecycle event."""

    id: int
    scan_id: str
    status: ScanStatus
    message: str
    created_at: str


class ScanEventsResponse(BaseModel):
    """Timeline response for one scan."""

    scan_id: str
    events: list[ScanEventResponse] = Field(default_factory=list)


class AgentReviewReportResponse(BaseModel):
    """Structured bounded-agent review for one completed scan."""

    scan_id: str
    requested: bool
    used: bool
    status: str | None = None
    verdict: str | None = None
    summary: str | None = None
    report: dict[str, object] | None = None


class OpenRouterModelResponse(BaseModel):
    """Frontend model-choice entry for OpenRouter."""

    id: str
    name: str
    description: str | None = None
    context_length: int | None = None
    max_completion_tokens: int | None = None
    modality: str | None = None
    prompt_price: str | None = None
    completion_price: str | None = None
    supported_parameters: list[str] = Field(default_factory=list)


class OpenRouterModelsResponse(BaseModel):
    """Normalized OpenRouter model catalog payload."""

    source: str
    fetched_at: int
    total_count: int
    items: list[OpenRouterModelResponse] = Field(default_factory=list)


class RuleDocResponse(BaseModel):
    """Rule documentation entry."""

    rule_id: str
    rule_family: str
    title: str
    category: str
    description: str
    remediation: str
    documentation_url: str


class RuleListResponse(BaseModel):
    """List of supported rule documentation entries."""

    items: list[RuleDocResponse] = Field(default_factory=list)
