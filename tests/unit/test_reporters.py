"""Unit tests for TerminalReporter."""

from pathlib import Path

from pyshield.core.models import (
    Confidence,
    FileDiagnostic,
    Finding,
    ScanResult,
    ScanSummary,
    Severity,
)
from pyshield.reporters.terminal import TerminalReporter


class TestTerminalReporter:
    def test_render_clean_report(self) -> None:
        result = ScanResult(
            findings=[],
            diagnostics=[],
            summary=ScanSummary(files_scanned=5, files_failed=0, duration_seconds=0.045),
        )
        reporter = TerminalReporter()
        output = reporter.render_to_string(result)
        assert "PyShield Security Scan" in output
        assert "Files scanned: 5" in output
        assert "No security findings detected" in output
        assert "Total findings: 0" in output

    def test_render_findings_and_summary(self) -> None:
        finding = Finding(
            rule_id="PS101",
            title="Dangerous eval() usage",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            file_path=Path("src/app.py"),
            line=42,
            column=10,
            message="eval call detected",
            description="Remote code execution risk",
            remediation="Use literal_eval instead",
            snippet="eval(payload)",
        )
        result = ScanResult(
            findings=[finding],
            diagnostics=[],
            summary=ScanSummary(
                files_scanned=1,
                findings_count={
                    Severity.CRITICAL: 1,
                    Severity.HIGH: 0,
                    Severity.MEDIUM: 0,
                    Severity.LOW: 0,
                },
                duration_seconds=0.01,
            ),
        )
        reporter = TerminalReporter()
        output = reporter.render_to_string(result)
        assert "PS101" in output
        assert "Dangerous eval() usage" in output
        assert "src/app.py:42:10" in output
        assert "Critical:" in output
        assert "Total findings: 1" in output

    def test_render_diagnostics(self) -> None:
        diag = FileDiagnostic(
            file_path=Path("syntax_error.py"),
            error_type="SyntaxError",
            message="invalid syntax",
            line=10,
            column=5,
        )
        result = ScanResult(
            findings=[],
            diagnostics=[diag],
            summary=ScanSummary(files_scanned=0, files_failed=1),
        )
        reporter = TerminalReporter()
        output = reporter.render_to_string(result)
        assert "Files with diagnostics: 1" in output
        assert "SyntaxError" in output
        assert "syntax_error.py:10:5" in output
