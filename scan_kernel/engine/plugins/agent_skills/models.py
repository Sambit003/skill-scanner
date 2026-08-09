"""Shared models for the ScanKernel scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from scan_kernel.engine.plugins.agent_skills.state import ScanKernelState


class Severity(StrEnum):
    """Severity levels for findings (used by all analyzers)."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Location:
    """Location of a finding within a file (used by all analyzers)."""

    file: str
    start_line: int
    end_line: int | None = None


@dataclass
class AnalyzerFinding:
    """
    Common finding type produced by any deterministic analyzer.
    Converted to Finding for pipeline state; use severity, location, tags for consistency.
    """

    rule_id: str
    message: str
    severity: Severity
    location: Location
    confidence: float = 0.5
    remediation: str | None = None
    tags: list[str] = field(default_factory=list)
    context: str | None = None
    matched_text: str | None = None


@dataclass
class Finding:
    """Finding model for pipeline state and report output."""

    rule_id: str
    message: str
    severity: str = "LOW"
    confidence: float = 0.5
    file: str = "SKILL.md"
    start_line: int = 1
    end_line: int | None = None
    category: str | None = None
    pattern: str | None = None
    finding: str | None = None  # short matched snippet
    explanation: str | None = None
    remediation: str | None = None
    code_snippet: str | None = None
    intent: str | None = None
    tags: list[str] = field(default_factory=list)
    context: str | None = None
    matched_text: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable dict representation (full finding shape)."""
        return {
            "id": self.rule_id,
            "category": self.category,
            "pattern": self.pattern,
            "severity": self.severity,
            "confidence": self.confidence,
            "location": {
                "file": self.file,
                "start_line": self.start_line,
                "end_line": self.end_line,
            },
            "finding": self.finding,
            "explanation": self.explanation or self.message,
            "remediation": self.remediation,
            "code_snippet": self.code_snippet or self.context,
            "intent": self.intent,
            "tags": list(self.tags),
        }

    def __str__(self) -> str:
        return f"{self.rule_id}: {self.message} ({self.file}:{self.start_line})"


class AnalyzerPlugin(Protocol):
    """Analyzer plugin protocol: name/stage/availability and an ``analyze`` entry point."""

    name: str
    stage: str
    requires_api_key: bool

    def analyze(self, state: ScanKernelState) -> list[Finding]:
        """Analyze pipeline state and return findings."""

    def is_available(self) -> bool:
        """Return whether the analyzer can run in current environment."""
