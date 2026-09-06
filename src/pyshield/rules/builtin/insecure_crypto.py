"""PS302: Insecure cryptographic algorithm rule."""

import ast

from pyshield.core.models import Confidence, Finding, Severity
from pyshield.rules.base import ASTContext, BaseRule

# Known insecure cipher classes / functions
INSECURE_CIPHER_NAMES: frozenset[str] = frozenset(
    {
        "DES",
        "DES3",
        "TripleDES",
        "ARC4",
        "RC4",
        "Blowfish",
        "IDEA",
        "des",
        "triple_des",
    }
)

# Known insecure crypto library module prefixes
KNOWN_CRYPTO_MODULES: tuple[str, ...] = (
    "Crypto.Cipher",
    "cryptography.hazmat.primitives.ciphers.algorithms",
    "pyDes",
)


class InsecureCryptoRule(BaseRule):
    """Detects use of deprecated or broken symmetric encryption algorithms."""

    rule_id = "PS302"
    title = "Use of insecure cryptographic algorithm"
    description = (
        "Legacy ciphers such as DES, Triple-DES (3DES), RC4/ARC4, and Blowfish have known "
        "cryptanalytic weaknesses, small block sizes, or practical collision vulnerabilities."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe = "CWE-327"
    remediation = (
        "Replace legacy algorithms with modern authenticated encryption standards, such as "
        "AES-GCM (AES-256-GCM) or ChaCha20-Poly1305."
    )

    def _is_insecure_crypto_import(self, qualified_name: str) -> bool:
        """Check if an imported symbol belongs to known cryptography modules."""
        for mod in KNOWN_CRYPTO_MODULES:
            if qualified_name.startswith(mod):
                return True
        return False

    def check(self, context: ASTContext) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(context.tree):
            if not isinstance(node, ast.Call):
                continue

            cipher_name: str | None = None

            # Pattern 1: DES.new(...) or ARC4.new(...)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "new":
                if isinstance(node.func.value, ast.Name):
                    target_id = node.func.value.id
                    if target_id in INSECURE_CIPHER_NAMES:
                        imported = context.imports.get(target_id, "")
                        if self._is_insecure_crypto_import(imported):
                            cipher_name = target_id

            # Pattern 2: algorithms.TripleDES(...) or pyDes.des(...)
            elif isinstance(node.func, ast.Attribute) and node.func.attr in INSECURE_CIPHER_NAMES:
                if isinstance(node.func.value, ast.Name):
                    target_id = node.func.attr
                    mod_alias = node.func.value.id
                    imported_mod = context.imports.get(mod_alias, mod_alias)
                    if self._is_insecure_crypto_import(imported_mod):
                        cipher_name = target_id

            # Pattern 3: TripleDES(...) directly imported
            elif isinstance(node.func, ast.Name) and node.func.id in INSECURE_CIPHER_NAMES:
                target_id = node.func.id
                imported = context.imports.get(target_id, "")
                if self._is_insecure_crypto_import(imported):
                    cipher_name = target_id

            if cipher_name:
                findings.append(
                    self.create_finding(
                        context=context,
                        node=node,
                        message=(
                            f"Insecure cryptographic algorithm '{cipher_name}' detected. "
                            "Use AES-GCM or ChaCha20-Poly1305 instead."
                        ),
                    )
                )

        return findings
