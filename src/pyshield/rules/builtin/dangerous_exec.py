"""PS102: Dangerous exec() rule."""

import ast

from pyshield.core.models import Confidence, Finding, Severity
from pyshield.rules.base import ASTContext, BaseRule


class DangerousExecRule(BaseRule):
    """Detects calls to Python's built-in exec() function."""

    rule_id = "PS102"
    title = "Dangerous exec() usage"
    description = (
        "The built-in exec() function dynamically executes arbitrary Python code statements. "
        "Supplying untrusted data allows attackers to execute arbitrary commands and take "
        "complete control of the application."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    cwe = "CWE-95"
    remediation = (
        "Avoid dynamic statement execution with exec(). "
        "Redesign code to use predefined dispatch mappings, functions, or safe configuration files."
    )

    def check(self, context: ASTContext) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(context.tree):
            if isinstance(node, ast.Call):
                # Detect actual direct calls to exec(...)
                # Never flag attribute calls like runner.exec(), app.exec(), or db.exec()
                if isinstance(node.func, ast.Name) and node.func.id == "exec":
                    finding = self.create_finding(
                        context=context,
                        node=node,
                        message=(
                            "Direct call to built-in exec() detected. "
                            "Potential arbitrary code execution."
                        ),
                    )
                    findings.append(finding)

        return findings
