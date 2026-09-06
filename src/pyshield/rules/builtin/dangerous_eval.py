"""PS101: Dangerous eval() rule."""

import ast

from pyshield.core.models import Confidence, Finding, Severity
from pyshield.rules.base import ASTContext, BaseRule


class DangerousEvalRule(BaseRule):
    """Detects calls to Python's built-in eval() function."""

    rule_id = "PS101"
    title = "Dangerous eval() usage"
    description = (
        "The built-in eval() function parses and evaluates arbitrary Python expressions "
        "dynamically. When supplied with untrusted or externally influenced input, it enables "
        "Remote Code Execution (RCE)."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    cwe = "CWE-95"
    remediation = (
        "Avoid eval(). If evaluating literals, use ast.literal_eval(). "
        "For data deserialization, use structured parsers such as json.loads()."
    )

    def check(self, context: ASTContext) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(context.tree):
            if isinstance(node, ast.Call):
                # Detect actual direct calls to eval(...)
                # Never flag attribute calls like model.eval() or object.eval()
                if isinstance(node.func, ast.Name) and node.func.id == "eval":
                    finding = self.create_finding(
                        context=context,
                        node=node,
                        message=(
                            "Direct call to built-in eval() detected. "
                            "Potential arbitrary code execution."
                        ),
                    )
                    findings.append(finding)

        return findings
