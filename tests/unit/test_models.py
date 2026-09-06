"""Unit tests for PyShield core data models."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from pyshield.core.models import (
    Confidence,
    FileDiagnostic,
    Finding,
    ScanResult,
    ScanSummary,
    Severity,
)


class TestModels:
    def test_severity_ordering(self) -> None:
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW >= Severity.LOW
        assert Severity.LOW <= Severity.HIGH
        assert not (Severity.LOW > Severity.CRITICAL)

    def test_finding_immutability(self) -> None:
        finding = Finding(
            rule_id="PS101",
            title="Dangerous eval()",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            file_path=Path("test.py"),
            line=10,
            column=5,
            message="eval detected",
            description="Arbitrary code execution",
            remediation="Do not use eval",
        )
        with pytest.raises(ValidationError):
            # Finding is frozen
            finding.line = 20  # type: ignore[misc]

    def test_scan_summary_totals(self) -> None:
        summary = ScanSummary(
            files_scanned=5,
            files_failed=1,
            findings_count={
                Severity.CRITICAL: 2,
                Severity.HIGH: 1,
                Severity.MEDIUM: 0,
                Severity.LOW: 3,
            },
            duration_seconds=0.123,
        )
        assert summary.total_findings == 6
        assert summary.files_scanned == 5

    def test_scan_result_composition(self) -> None:
        diag = FileDiagnostic(
            file_path=Path("bad.py"),
            error_type="SyntaxError",
            message="invalid syntax",
            line=1,
            column=2,
        )
        finding = Finding(
            rule_id="PS103",
            title="os.system()",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            file_path=Path("script.py"),
            line=2,
            column=1,
            message="os.system call",
            description="Command injection risk",
            remediation="Use subprocess.run",
        )
        result = ScanResult(
            findings=[finding],
            diagnostics=[diag],
            summary=ScanSummary(files_scanned=1, files_failed=1),
        )
        assert len(result.findings) == 1
        assert len(result.diagnostics) == 1
        assert result.summary.files_scanned == 1
