"""PS303: Insecure randomness in security-sensitive context rule."""

import ast
import re

from pyshield.core.models import Confidence, Finding, Severity
from pyshield.rules.base import ASTContext, BaseRule

RANDOM_FUNCS: frozenset[str] = frozenset(
    {
        "random",
        "randint",
        "choice",
        "choices",
        "sample",
        "randrange",
        "getrandbits",
        "uniform",
    }
)

SECURITY_IDENTIFIER_PATTERN: re.Pattern[str] = re.compile(
    r"(?:^|[_-])(token|secret|password|passwd|otp|session(?:_?id)?|auth|salt|nonce|pin|csrf)(?:$|[_-])",
    re.IGNORECASE,
)


class InsecureRandomRule(BaseRule):
    """Detects use of standard random module for generating security-sensitive values."""

    rule_id = "PS303"
    title = "Insecure randomness in security-sensitive context"
    description = (
        "Python's standard 'random' module produces pseudo-random numbers using the Mersenne "
        "Twister algorithm, which is completely deterministic and cryptographically insecure. "
        "It must not be used for security tokens, passwords, session IDs, salts, or keys."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe = "CWE-330"
    remediation = (
        "Use Python's standard 'secrets' module (secrets.token_hex(), secrets.token_urlsafe(), "
        "secrets.choice()) for cryptographically secure randomness."
    )

    def _is_random_call(self, node: ast.Call, context: ASTContext) -> bool:
        """Check if call is to Python's standard random module."""
        # Pattern 1: random.randint(...)
        if isinstance(node.func, ast.Attribute) and node.func.attr in RANDOM_FUNCS:
            if isinstance(node.func.value, ast.Name):
                resolved_mod = context.resolve_name(node.func.value.id)
                if resolved_mod == "random" or node.func.value.id == "random":
                    return True

        # Pattern 2: from random import randint; randint(...)
        elif isinstance(node.func, ast.Name) and node.func.id in RANDOM_FUNCS:
            imported = context.imports.get(node.func.id, "")
            parts = imported.rsplit(".", 1)
            if len(parts) == 2 and parts[0] == "random" and parts[1] in RANDOM_FUNCS:
                return True

        return False

    def check(self, context: ASTContext) -> list[Finding]:
        findings: list[Finding] = []

        # Traverse AST maintaining scope context (e.g. current enclosing function)
        for node in ast.walk(context.tree):
            # Check variable assignments: token = random.randint(...)
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    target_name = getattr(target, "id", None) or getattr(target, "attr", None)
                    if target_name and SECURITY_IDENTIFIER_PATTERN.search(target_name):
                        # Walk the value AST to see if random call is used
                        for subnode in ast.walk(node.value):
                            if isinstance(subnode, ast.Call) and self._is_random_call(
                                subnode, context
                            ):
                                findings.append(
                                    self.create_finding(
                                        context=context,
                                        node=node,
                                        message=(
                                            f"Insecure 'random' module used to generate "
                                            f"security-sensitive value '{target_name}'."
                                        ),
                                    )
                                )
                                break

            elif isinstance(node, ast.AnnAssign):
                target_name = getattr(node.target, "id", None) or getattr(node.target, "attr", None)
                if (
                    target_name
                    and SECURITY_IDENTIFIER_PATTERN.search(target_name)
                    and node.value is not None
                ):
                    for subnode in ast.walk(node.value):
                        if isinstance(subnode, ast.Call) and self._is_random_call(subnode, context):
                            findings.append(
                                self.create_finding(
                                    context=context,
                                    node=node,
                                    message=(
                                        f"Insecure 'random' module used to generate "
                                        f"security-sensitive value '{target_name}'."
                                    ),
                                )
                            )
                            break

            # Check function definitions whose name is security-sensitive: def generate_token():
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if SECURITY_IDENTIFIER_PATTERN.search(node.name):
                    # Check return statements inside this function
                    for stmt in ast.walk(node):
                        if isinstance(stmt, ast.Return) and stmt.value is not None:
                            for subnode in ast.walk(stmt.value):
                                if isinstance(subnode, ast.Call) and self._is_random_call(
                                    subnode, context
                                ):
                                    findings.append(
                                        self.create_finding(
                                            context=context,
                                            node=stmt,
                                            message=(
                                                f"Insecure 'random' module used in "
                                                f"security-sensitive function '{node.name}'."
                                            ),
                                        )
                                    )

        return findings
