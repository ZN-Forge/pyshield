"""PS104: Unsafe subprocess rule."""

import ast
from typing import Any

from pyshield.core.models import Confidence, Finding, Severity
from pyshield.rules.base import ASTContext, BaseRule

SUBPROCESS_FUNCS: frozenset[str] = frozenset(
    {
        "run",
        "Popen",
        "call",
        "check_call",
        "check_output",
    }
)


def is_truthy_literal(node: ast.AST) -> bool:
    """Return True only if node is an explicit compile-time truthy literal (e.g. True or 1)."""
    if isinstance(node, ast.Constant):
        val: Any = node.value
        # Exclude explicit False, None, 0, or empty containers
        if val is True:
            return True
        if isinstance(val, int) and val not in (0, False):
            return True
    return False


class UnsafeSubprocessRule(BaseRule):
    """Detects calls to subprocess execution APIs with shell=True."""

    rule_id = "PS104"
    title = "Unsafe subprocess execution with shell=True"
    description = (
        "Invoking subprocess APIs with shell=True executes commands through the system shell. "
        "If any portion of the command string is derived from untrusted input, it exposes the "
        "application to severe command injection vulnerabilities."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe = "CWE-78"
    remediation = (
        "Set shell=False (the default) and pass arguments as a list of strings. "
        "Example: subprocess.run(['ls', '-la'], shell=False)"
    )

    def check(self, context: ASTContext) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(context.tree):
            if not isinstance(node, ast.Call):
                continue

            target_func_name: str | None = None

            # Pattern 1: subprocess.run(...) or alias.run(...)
            if isinstance(node.func, ast.Attribute) and node.func.attr in SUBPROCESS_FUNCS:
                if isinstance(node.func.value, ast.Name):
                    resolved_mod = context.resolve_name(node.func.value.id)
                    if resolved_mod == "subprocess" or node.func.value.id == "subprocess":
                        target_func_name = node.func.attr

            # Pattern 2: run(...) imported from subprocess
            elif isinstance(node.func, ast.Name):
                imported_source = context.imports.get(node.func.id)
                if imported_source:
                    parts = imported_source.rsplit(".", 1)
                    if (
                        len(parts) == 2
                        and parts[0] == "subprocess"
                        and parts[1] in SUBPROCESS_FUNCS
                    ):
                        target_func_name = parts[1]

            if target_func_name is None:
                continue

            # Inspect keyword arguments for shell=True or truthy literal
            has_shell_true = False
            for kw in node.keywords:
                if kw.arg == "shell":
                    if is_truthy_literal(kw.value):
                        has_shell_true = True
                    break

            if has_shell_true:
                findings.append(
                    self.create_finding(
                        context=context,
                        node=node,
                        message=(
                            f"subprocess.{target_func_name}() invoked with shell=True. "
                            "This creates command injection vulnerability risks."
                        ),
                    )
                )

        return findings
