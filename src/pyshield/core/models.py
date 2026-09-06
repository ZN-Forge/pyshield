"""Core data models for PyShield security analysis."""

from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Vulnerability severity levels ordered by criticality."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def level(self) -> int:
        """Integer priority level for comparison (higher = more severe)."""
        mapping = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return mapping[self]

    def __ge__(self, other: Any) -> bool:
        if isinstance(other, Severity):
            return self.level >= other.level
        return NotImplemented

    def __gt__(self, other: Any) -> bool:
        if isinstance(other, Severity):
            return self.level > other.level
        return NotImplemented

    def __le__(self, other: Any) -> bool:
        if isinstance(other, Severity):
            return self.level <= other.level
        return NotImplemented

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, Severity):
            return self.level < other.level
        return NotImplemented


class Confidence(StrEnum):
    """Confidence levels in the deterministic finding."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Finding(BaseModel):
    """Represents a deterministic security finding detected by a rule."""

    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(description="Unique stable rule identifier, e.g. PS101")
    title: str = Field(description="Brief title of the finding")
    severity: Severity = Field(description="Severity classification")
    confidence: Confidence = Field(description="Confidence level in the match")
    file_path: Path = Field(description="Path to the file where the finding was detected")
    line: int = Field(description="Line number (1-indexed)")
    column: int = Field(description="Column number (1-indexed)")
    end_line: int | None = Field(default=None, description="Ending line number if known")
    end_column: int | None = Field(default=None, description="Ending column number if known")
    message: str = Field(description="Context-specific finding message")
    description: str = Field(description="Detailed explanation of the vulnerability risk")
    remediation: str = Field(description="Actionable guidance to remediate the issue")
    cwe: str | None = Field(default=None, description="Common Weakness Enumeration ID, e.g. CWE-95")
    snippet: str | None = Field(default=None, description="Safe code excerpt at finding location")


class FileDiagnostic(BaseModel):
    """Represents a non-fatal diagnostic or error encountered when processing a file."""

    model_config = ConfigDict(frozen=True)

    file_path: Path = Field(description="Path to the file that caused the diagnostic")
    error_type: str = Field(description="Type of error (e.g. SyntaxError, UnicodeDecodeError)")
    message: str = Field(description="Detailed diagnostic message")
    line: int | None = Field(default=None, description="Line number if available")
    column: int | None = Field(default=None, description="Column number if available")


class ScanSummary(BaseModel):
    """Summary metrics of a scan execution."""

    files_scanned: int = Field(default=0, description="Total number of files parsed successfully")
    files_failed: int = Field(default=0, description="Number of files that failed parsing/reading")
    findings_count: dict[Severity, int] = Field(
        default_factory=lambda: {s: 0 for s in Severity},
        description="Count of findings per severity level",
    )
    duration_seconds: float = Field(default=0.0, description="Scan execution duration in seconds")

    @property
    def total_findings(self) -> int:
        """Total number of findings detected across all severities."""
        return sum(self.findings_count.values())


class ScanResult(BaseModel):
    """Aggregated result of a scan execution."""

    findings: list[Finding] = Field(default_factory=list, description="All detected findings")
    diagnostics: list[FileDiagnostic] = Field(
        default_factory=list, description="Diagnostics for failed files"
    )
    summary: ScanSummary = Field(
        default_factory=ScanSummary, description="Summary metrics of the scan"
    )
