"""Rule PS703: Detects insecure cookie security settings."""

import ast

from pyshield.core.models import Confidence, Finding, Severity
from pyshield.rules.base import ASTContext, BaseRule

INSECURE_COOKIE_SETTINGS = {
    "SESSION_COOKIE_SECURE": (
        "Session cookies are allowed over unencrypted HTTP (SESSION_COOKIE_SECURE = False)."
    ),
    "CSRF_COOKIE_SECURE": (
        "CSRF cookies are allowed over unencrypted HTTP (CSRF_COOKIE_SECURE = False)."
    ),
    "SESSION_COOKIE_HTTPONLY": (
        "Session cookies are accessible to client-side scripts (SESSION_COOKIE_HTTPONLY = False)."
    ),
}


class InsecureCookieRule(BaseRule):
    """Detects insecure cookie security configuration settings."""

    rule_id = "PS703"
    title = "Insecure cookie configuration"
    description = (
        "Detects security-sensitive cookie configurations where secure transmission "
        "(SESSION_COOKIE_SECURE, CSRF_COOKIE_SECURE) or HttpOnly flags are disabled, "
        "exposing sensitive cookies to transmission interception or cross-site scripting (XSS)."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    cwe = "CWE-614"
    remediation = (
        "Enable secure cookie flags: set SESSION_COOKIE_SECURE = True, CSRF_COOKIE_SECURE = True, "
        "and SESSION_COOKIE_HTTPONLY = True in production settings."
    )

    def check(self, context: ASTContext) -> list[Finding]:
        """Scan AST for insecure cookie flag assignments."""
        findings: list[Finding] = []

        for node in ast.walk(context.tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in INSECURE_COOKIE_SETTINGS:
                        if self._is_falsy_literal(node.value):
                            msg = INSECURE_COOKIE_SETTINGS[target.id]
                            findings.append(
                                self.create_finding(context=context, node=node, message=msg)
                            )
            elif isinstance(node, ast.AnnAssign):
                if isinstance(node.target, ast.Name) and node.target.id in INSECURE_COOKIE_SETTINGS:
                    if node.value is not None and self._is_falsy_literal(node.value):
                        msg = INSECURE_COOKIE_SETTINGS[node.target.id]
                        findings.append(
                            self.create_finding(context=context, node=node, message=msg)
                        )

        return findings

    @staticmethod
    def _is_falsy_literal(node: ast.AST) -> bool:
        """Return True if node is explicitly False or 0."""
        if isinstance(node, ast.Constant):
            if node.value is False or node.value == 0:
                return True
        return False
