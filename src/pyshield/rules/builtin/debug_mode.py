"""Rule PS701: Detects debug mode enabled in configuration settings."""

import ast

from pyshield.core.models import Confidence, Finding, Severity
from pyshield.rules.base import ASTContext, BaseRule


class DebugModeRule(BaseRule):
    """Detects debug mode explicitly enabled (DEBUG = True)."""

    rule_id = "PS701"
    title = "Debug mode enabled"
    description = (
        "Detects debug mode explicitly enabled in configuration settings, which can leak "
        "sensitive stack traces, environment variables, and internal state in production."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe = "CWE-489"
    remediation = (
        "Set DEBUG = False in production environments or load the configuration "
        "securely from environment variables."
    )

    def check(self, context: ASTContext) -> list[Finding]:
        """Scan AST for DEBUG = True assignments."""
        findings: list[Finding] = []

        for node in ast.walk(context.tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "DEBUG":
                        if self._is_truthy_literal(node.value):
                            findings.append(
                                self.create_finding(
                                    context=context,
                                    node=node,
                                    message="Debug mode is explicitly enabled (DEBUG = True).",
                                )
                            )
            elif isinstance(node, ast.AnnAssign):
                if isinstance(node.target, ast.Name) and node.target.id == "DEBUG":
                    if node.value is not None and self._is_truthy_literal(node.value):
                        findings.append(
                            self.create_finding(
                                context=context,
                                node=node,
                                message="Debug mode is explicitly enabled (DEBUG = True).",
                            )
                        )

        return findings

    @staticmethod
    def _is_truthy_literal(node: ast.AST) -> bool:
        """Return True if node is a literal True or 1, not False or 0."""
        if isinstance(node, ast.Constant):
            if node.value is True or node.value == 1:
                return True
        return False
