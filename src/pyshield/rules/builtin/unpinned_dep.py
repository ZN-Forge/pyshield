"""Rule PS802: Detects unpinned dependency specifications."""

from pyshield.core.models import Confidence, Finding, Severity
from pyshield.dependencies.models import Dependency, DependencySourceType
from pyshield.rules.base import ASTContext, BaseRule

VALID_VERSION_OPERATORS = ("==", ">=", "<=", "~=", "!=", "<", ">", "===")


class UnpinnedDepRule(BaseRule):
    """Detects unpinned dependency declarations in requirements.txt or pyproject.toml."""

    rule_id = "PS802"
    title = "Unpinned dependency specification"
    description = (
        "Detects dependency declarations without meaningful version constraints, which can lead "
        "to unexpected breaking changes or automatic installation of compromised future releases."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    cwe = "CWE-1104"
    remediation = (
        "Add a version constraint to the dependency declaration "
        "(e.g. 'requests>=2.31.0' or 'requests==2.31.0')."
    )

    def check(self, context: ASTContext) -> list[Finding]:
        """No-op for AST analysis; dependency rules operate via check_dependency."""
        return []

    def check_dependency(
        self,
        dependency: Dependency,
        snippet: str | None = None,
    ) -> Finding | None:
        """Evaluate dependency for version constraint pinning.

        uv.lock is always exempt because lockfiles record resolved exact versions.
        """
        # uv.lock is always exempt
        if dependency.source_type == DependencySourceType.UV_LOCK:
            return None

        # Check if a meaningful version constraint exists
        specifier = dependency.specifier
        if specifier is None or not specifier.strip():
            # Unpinned!
            msg = f"Dependency '{dependency.raw_name}' is declared without a version constraint."
            return Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                confidence=self.confidence,
                file_path=dependency.source_file,
                line=dependency.line or 1,
                column=1,
                end_line=dependency.line,
                end_column=None,
                message=msg,
                description=self.description,
                remediation=self.remediation,
                cwe=self.cwe,
                snippet=snippet or dependency.raw_name,
            )

        # If specifier has a recognised comparison operator, it is constrained
        spec_clean = specifier.strip()
        if any(op in spec_clean for op in VALID_VERSION_OPERATORS):
            return None

        # Fallback: if specifier has text but no operator, flag as unpinned
        msg = (
            f"Dependency '{dependency.raw_name}' lacks a standard "
            f"version constraint ({spec_clean})."
        )
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            confidence=self.confidence,
            file_path=dependency.source_file,
            line=dependency.line or 1,
            column=1,
            end_line=dependency.line,
            end_column=None,
            message=msg,
            description=self.description,
            remediation=self.remediation,
            cwe=self.cwe,
            snippet=snippet or f"{dependency.raw_name} {specifier}",
        )
