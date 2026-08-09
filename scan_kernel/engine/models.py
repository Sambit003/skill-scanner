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
class ScanConfig:
    target: str
    asset_type: str = "agent_skill"
    output_formats: List[ReportFormat] = field(default_factory=lambda: [ReportFormat.JSON])
    yara_rules_dir: Optional[Path] = None
    baseline_path: Optional[Path] = None
    show_suppressed: bool = False
    timeout_seconds: Optional[float] = None

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

@dataclass
class ScanResult:
    summary: ScanSummary
    findings: List[Dict[str, Any]]
    reports: Dict[ReportFormat, ReportContent]
    raw_state: Optional[Dict[str, Any]] = None
