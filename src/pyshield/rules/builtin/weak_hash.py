"""PS301: Weak hash algorithm rule."""

import ast

from pyshield.core.models import Confidence, Finding, Severity
from pyshield.rules.base import ASTContext, BaseRule

WEAK_HASH_NAMES: frozenset[str] = frozenset({"md5", "sha1"})


class WeakHashRule(BaseRule):
    """Detects use of weak or broken cryptographic hash algorithms (MD5 and SHA-1)."""

    rule_id = "PS301"
    title = "Use of weak cryptographic hash algorithm"
    description = (
        "MD5 and SHA-1 hashing algorithms have known cryptographic weaknesses and practical "
        "collision attacks. They are unsuitable for security-sensitive integrity verification, "
        "digital signatures, or authentication."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    cwe = "CWE-328"
    remediation = (
        "Use SHA-256 or SHA-3 (e.g. hashlib.sha256()) for general hashing. For password "
        "storage, use dedicated password hashing algorithms such as argon2, bcrypt, or scrypt."
    )

    def _has_usedforsecurity_false(self, node: ast.Call) -> bool:
        """Return True if call explicitly specifies usedforsecurity=False."""
        for kw in node.keywords:
            if kw.arg == "usedforsecurity":
                if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    return True
        return False

    def check(self, context: ASTContext) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(context.tree):
            if not isinstance(node, ast.Call):
                continue

            # If explicitly marked as not used for security, ignore
            if self._has_usedforsecurity_false(node):
                continue

            algo_name: str | None = None

            # Pattern 1: hashlib.md5(...) or alias.sha1(...)
            if isinstance(node.func, ast.Attribute) and node.func.attr in WEAK_HASH_NAMES:
                if isinstance(node.func.value, ast.Name):
                    resolved_mod = context.resolve_name(node.func.value.id)
                    if resolved_mod == "hashlib" or node.func.value.id == "hashlib":
                        algo_name = node.func.attr.upper()

            # Pattern 2: hashlib.new("md5", ...)
            elif isinstance(node.func, ast.Attribute) and node.func.attr == "new":
                if isinstance(node.func.value, ast.Name):
                    resolved_mod = context.resolve_name(node.func.value.id)
                    if resolved_mod == "hashlib" or node.func.value.id == "hashlib":
                        # Check first argument or name kwarg
                        target_name = None
                        if node.args and isinstance(node.args[0], ast.Constant):
                            if isinstance(node.args[0].value, str):
                                target_name = node.args[0].value.lower()
                        for kw in node.keywords:
                            if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                                if isinstance(kw.value.value, str):
                                    target_name = kw.value.value.lower()
                        if target_name in WEAK_HASH_NAMES:
                            algo_name = target_name.upper()

            # Pattern 3: from hashlib import md5; md5(...)
            elif isinstance(node.func, ast.Name):
                imported_source = context.imports.get(node.func.id)
                if imported_source:
                    parts = imported_source.rsplit(".", 1)
                    if len(parts) == 2 and parts[0] == "hashlib" and parts[1] in WEAK_HASH_NAMES:
                        algo_name = parts[1].upper()

            if algo_name:
                findings.append(
                    self.create_finding(
                        context=context,
                        node=node,
                        message=(
                            f"Weak hash algorithm {algo_name} detected. "
                            "Use SHA-256 or stronger instead."
                        ),
                    )
                )

        return findings
