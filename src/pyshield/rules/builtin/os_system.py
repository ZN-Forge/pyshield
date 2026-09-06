"""PS103: os.system() rule."""

import ast

from pyshield.core.models import Confidence, Finding, Severity
from pyshield.rules.base import ASTContext, BaseRule


class OsSystemRule(BaseRule):
    """Detects calls to os.system() which executes commands via a shell."""

    rule_id = "PS103"
    title = "Use of os.system()"
    description = (
        "The os.system() function passes its command string directly to the underlying shell. "
        "This is susceptible to command injection attacks if any part of the command "
        "contains untrusted data."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe = "CWE-78"
    remediation = (
        "Replace os.system() with subprocess.run() using argument lists and shell=False. "
        "Example: subprocess.run(['cmd', arg1, arg2], check=True)"
    )

    def check(self, context: ASTContext) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(context.tree):
            if not isinstance(node, ast.Call):
                continue

            is_os_system = False

            # Pattern 1: os.system(...) or alias.system(...) where alias resolves to 'os'
            if isinstance(node.func, ast.Attribute) and node.func.attr == "system":
                if isinstance(node.func.value, ast.Name):
                    resolved_mod = context.resolve_name(node.func.value.id)
                    if resolved_mod == "os" or node.func.value.id == "os":
                        is_os_system = True

            # Pattern 2: system(...) where 'system' was explicitly imported from 'os'
            elif isinstance(node.func, ast.Name):
                imported_source = context.imports.get(node.func.id)
                if imported_source == "os.system":
                    is_os_system = True

            if is_os_system:
                findings.append(
                    self.create_finding(
                        context=context,
                        node=node,
                        message=(
                            "Call to os.system() detected. "
                            "Use subprocess with argument lists instead."
                        ),
                    )
                )

        return findings
