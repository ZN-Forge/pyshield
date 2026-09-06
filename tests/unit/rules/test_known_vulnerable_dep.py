"""Unit tests for PS801: KnownVulnerableDepRule."""

from pathlib import Path

from pyshield.core.models import Severity
from pyshield.dependencies.models import (
    Dependency,
    DependencySourceType,
    ProviderStatus,
    Vulnerability,
    VulnerabilityLookupResult,
)
from pyshield.rules.builtin.known_vulnerable_dep import KnownVulnerableDepRule


class TestKnownVulnerableDepRule:
    def setup_method(self) -> None:
        self.rule = KnownVulnerableDepRule()
        self.dummy_dep = Dependency(
            name="vulnerable-pkg",
            raw_name="Vulnerable-Pkg",
            version="1.0.0",
            specifier="==1.0.0",
            source_file=Path("requirements.txt"),
            source_type=DependencySourceType.REQUIREMENTS_TXT,
            line=5,
        )

    def test_vulnerable_dependency_detected(self) -> None:
        vuln = Vulnerability(
            id="GHSA-test-1234",
            summary="Remote code execution in vulnerable-pkg",
            aliases=["CVE-2023-12345"],
            fixed_version="1.0.1",
            severity=Severity.HIGH,
        )
        lookup = VulnerabilityLookupResult(
            status=ProviderStatus.AVAILABLE,
            vulnerabilities=[vuln],
        )

        findings = self.rule.check_dependency(
            self.dummy_dep, lookup, snippet="Vulnerable-Pkg==1.0.0"
        )

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "PS801"
        assert f.severity == Severity.HIGH
        assert f.cwe == "CWE-1395"
        assert f.line == 5
        assert "CVE-2023-12345" in f.message
        assert "1.0.1" in f.remediation

    def test_clean_dependency_no_findings(self) -> None:
        lookup = VulnerabilityLookupResult(
            status=ProviderStatus.AVAILABLE,
            vulnerabilities=[],
        )

        findings = self.rule.check_dependency(self.dummy_dep, lookup)
        assert len(findings) == 0

    def test_unavailable_provider_no_findings(self) -> None:
        lookup = VulnerabilityLookupResult(
            status=ProviderStatus.UNAVAILABLE,
            vulnerabilities=[],
            error_message="Network unreachable",
        )

        findings = self.rule.check_dependency(self.dummy_dep, lookup)
        assert len(findings) == 0
