"""Rule PS704: Detects insecure host or CORS wildcard configuration."""

import ast

from pyshield.core.models import Confidence, Finding, Severity
from pyshield.rules.base import ASTContext, BaseRule

CORS_ALL_ORIGINS_SETTINGS = {"CORS_ALLOW_ALL_ORIGINS", "CORS_ORIGIN_ALLOW_ALL"}


class InsecureHostRule(BaseRule):
    """Detects wildcard '*' in ALLOWED_HOSTS or CORS_ALLOW_ALL_ORIGINS = True."""

    rule_id = "PS704"
    title = "Insecure host or CORS wildcard configuration"
    description = (
        "Detects overly permissive host or cross-origin (CORS) wildcard configurations "
        "(e.g. ALLOWED_HOSTS = ['*'] or CORS_ALLOW_ALL_ORIGINS = True), exposing the application "
        "to DNS rebinding, HTTP Host header poisoning, or unauthorized cross-origin requests."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe = "CWE-346"
    remediation = (
        "Specify explicit trusted domain names in ALLOWED_HOSTS and restrict CORS origins "
        "to trusted domains rather than using unrestricted wildcards."
    )

    def check(self, context: ASTContext) -> list[Finding]:
        """Scan AST for ALLOWED_HOSTS wildcard or CORS allow-all settings."""
        findings: list[Finding] = []

        for node in ast.walk(context.tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        finding = self._check_assignment(target.id, node.value, node, context)
                        if finding:
                            findings.append(finding)
            elif isinstance(node, ast.AnnAssign):
                if isinstance(node.target, ast.Name) and node.value is not None:
                    finding = self._check_assignment(node.target.id, node.value, node, context)
                    if finding:
                        findings.append(finding)

        return findings

    def _check_assignment(
        self,
        var_name: str,
        value_node: ast.AST,
        parent_node: ast.AST,
        context: ASTContext,
    ) -> Finding | None:
        """Evaluate variable name and assignment value against insecure patterns."""
        # 1. ALLOWED_HOSTS with wildcard '*'
        if var_name == "ALLOWED_HOSTS":
            if self._contains_wildcard_string(value_node):
                return self.create_finding(
                    context=context,
                    node=parent_node,
                    message="ALLOWED_HOSTS contains wildcard '*' allowing requests from any host.",
                )

        # 2. CORS allow-all origins settings
        if var_name in CORS_ALL_ORIGINS_SETTINGS:
            if isinstance(value_node, ast.Constant):
                if value_node.value is True or value_node.value == 1:
                    return self.create_finding(
                        context=context,
                        node=parent_node,
                        message=(
                            f"{var_name} is set to True, allowing cross-origin "
                            "access from any domain."
                        ),
                    )

        return None

    @staticmethod
    def _contains_wildcard_string(node: ast.AST) -> bool:
        """Check if node is a list, tuple, or set containing a string literal '*'."""
        elements: list[ast.expr] = []
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            elements = node.elts

        for elt in elements:
            if isinstance(elt, ast.Constant) and elt.value == "*":
                return True
        return False
