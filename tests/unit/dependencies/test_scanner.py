"""Unit tests for DependencyScanner."""

from pathlib import Path
from unittest.mock import MagicMock

from pyshield.core.models import Severity
from pyshield.dependencies.models import (
    ProviderStatus,
    Vulnerability,
    VulnerabilityLookupResult,
)
from pyshield.dependencies.scanner import DependencyScanner
from pyshield.rules.builtin.known_vulnerable_dep import KnownVulnerableDepRule
from pyshield.rules.builtin.unpinned_dep import UnpinnedDepRule


class TestDependencyScanner:
    def test_scan_empty_files_list(self) -> None:
        scanner = DependencyScanner(rules=[KnownVulnerableDepRule(), UnpinnedDepRule()])
        findings, diagnostics = scanner.scan_files([])
        assert findings == []
        assert diagnostics == []

    def test_scan_file_read_error(self, tmp_path: Path) -> None:
        scanner = DependencyScanner(rules=[KnownVulnerableDepRule(), UnpinnedDepRule()])
        nonexistent = tmp_path / "does_not_exist_requirements.txt"
        findings, diagnostics = scanner.scan_files([nonexistent])
        assert findings == []
        assert len(diagnostics) == 1
        assert diagnostics[0].error_type == "ReadError"

    def test_scan_vulnerable_dependency_found(self, tmp_path: Path) -> None:
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("vulnerable-pkg==1.0.0\n", encoding="utf-8")

        mock_provider = MagicMock()
        mock_provider.query_batch.return_value = {
            ("vulnerable-pkg", "1.0.0"): VulnerabilityLookupResult(
                status=ProviderStatus.AVAILABLE,
                vulnerabilities=[
                    Vulnerability(
                        id="GHSA-test-9999",
                        summary="Severe flaw",
                        aliases=["CVE-2024-0001"],
                        fixed_version="1.0.1",
                        severity=Severity.CRITICAL,
                    )
                ],
            )
        }

        scanner = DependencyScanner(
            rules=[KnownVulnerableDepRule(), UnpinnedDepRule()],
            provider=mock_provider,
        )
        findings, diagnostics = scanner.scan_files([req_file])

        assert len(diagnostics) == 0
        assert len(findings) == 1
        assert findings[0].rule_id == "PS801"
        assert findings[0].severity == Severity.CRITICAL
        assert "CVE-2024-0001" in findings[0].message

    def test_scan_provider_unavailable_records_diagnostic(self, tmp_path: Path) -> None:
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("vulnerable-pkg==1.0.0\n", encoding="utf-8")

        mock_provider = MagicMock()
        mock_provider.query_batch.return_value = {
            ("vulnerable-pkg", "1.0.0"): VulnerabilityLookupResult(
                status=ProviderStatus.UNAVAILABLE,
                vulnerabilities=[],
                error_message="Connection timed out",
            )
        }

        scanner = DependencyScanner(
            rules=[KnownVulnerableDepRule(), UnpinnedDepRule()],
            provider=mock_provider,
        )
        findings, diagnostics = scanner.scan_files([req_file])

        assert len(findings) == 0
        assert len(diagnostics) == 1
        assert diagnostics[0].error_type == "VulnerabilityLookupUnavailable"
        assert "timed out" in diagnostics[0].message

    def test_scan_offline_records_diagnostic(self, tmp_path: Path) -> None:
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.31.0\n", encoding="utf-8")

        mock_provider = MagicMock()
        scanner = DependencyScanner(
            rules=[KnownVulnerableDepRule(), UnpinnedDepRule()],
            provider=mock_provider,
            offline=True,
        )
        findings, diagnostics = scanner.scan_files([req_file])

        assert mock_provider.query_batch.call_count == 0
        assert len(findings) == 0
        assert len(diagnostics) == 1
        assert diagnostics[0].error_type == "OfflineMode"
