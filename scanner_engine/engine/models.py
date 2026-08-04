from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

class ReportFormat(str, Enum):
    TERMINAL = "terminal"
    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"

@dataclass(frozen=True)
class AgentReviewConfig:
    enabled: bool = False
    provider: Optional[str] = None
    skill: Optional[str] = None
    prompt: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None

@dataclass(frozen=True)
class ScanConfig:
    target: str
    asset_type: str = "agent_skill"
    output_formats: List[ReportFormat] = field(default_factory=lambda: [ReportFormat.JSON])
    use_llm: bool = False
    yara_rules_dir: Optional[Path] = None
    baseline_path: Optional[Path] = None
    show_suppressed: bool = False
    agent_review: Optional[AgentReviewConfig] = None
    timeout_seconds: Optional[float] = None
    run_name: Optional[str] = None
    tags: List[str] = field(default_factory=list)

@dataclass
class ReportContent:
    format: ReportFormat
    content: str
    content_type: str

@dataclass
class ScanSummary:
    risk_score: int
    severity: str
    recommendation: str
    safe_to_install: bool
    findings_count: int
    findings_by_severity: Dict[str, int]
    findings_by_category: Dict[str, int]
    scanner_version: str
    scan_mode: str
    llm_requested: bool
    llm_used: bool
    agent_review_requested: bool
    agent_review_used: bool
    agent_review_status: Optional[str] = None
    agent_review_verdict: Optional[str] = None
    agent_review_summary: Optional[str] = None
    agent_review_report: Optional[str] = None

@dataclass
class ScanResult:
    summary: ScanSummary
    findings: List[Dict[str, Any]]
    reports: Dict[ReportFormat, ReportContent]
    raw_graph_state: Optional[Dict[str, Any]] = None
