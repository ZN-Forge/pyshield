"""Rule PS801: Detects dependencies with known security vulnerabilities."""

from pyshield.core.models import Confidence, Finding, Severity
from pyshield.dependencies.models import (
    Dependency,
    ProviderStatus,
    VulnerabilityLookupResult,
)
from pyshield.rules.base import ASTContext, BaseRule


class KnownVulnerableDepRule(BaseRule):
    """Detects dependencies with known vulnerabilities via vulnerability intelligence."""

    rule_id = "PS801"
    title = "Known vulnerable dependency detected"
    description = (
        "Detects installed or declared dependencies with published security vulnerabilities "
        "indexed in the OSV database."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe = "CWE-1395"
    remediation = "Upgrade the affected dependency to a non-vulnerable, patched version."

    def check(self, context: ASTContext) -> list[Finding]:
        """No-op for AST analysis; dependency rules operate via check_dependency."""
        return []

    def check_dependency(
        self,
        dependency: Dependency,
        lookup_result: VulnerabilityLookupResult,
        snippet: str | None = None,
    ) -> list[Finding]:
        """Generate findings for vulnerabilities discovered in dependency."""
        if lookup_result.status != ProviderStatus.AVAILABLE:
            return []

        findings: list[Finding] = []
        for vuln in lookup_result.vulnerabilities:
            alias_str = f" ({', '.join(vuln.aliases)})" if vuln.aliases else ""
            msg = (
                f"Dependency '{dependency.raw_name}' version {dependency.version} has "
                f"known vulnerability {vuln.id}{alias_str}: {vuln.summary}"
            )

            if vuln.fixed_version:
                remediation = (
                    f"Upgrade '{dependency.raw_name}' to version {vuln.fixed_version} or higher."
                )
            else:
                remediation = f"Upgrade '{dependency.raw_name}' to a patched version."

            finding = Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=vuln.severity,
                confidence=self.confidence,
                file_path=dependency.source_file,
                line=dependency.line or 1,
                column=1,
                end_line=dependency.line,
                end_column=None,
                message=msg,
                description=vuln.details or self.description,
                remediation=remediation,
                cwe=self.cwe,
                snippet=snippet or f"{dependency.raw_name}=={dependency.version}",
            )
            findings.append(finding)

        return findings
