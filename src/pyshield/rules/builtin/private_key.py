"""PS202: Private key material rule."""

import ast
import re

from pyshield.core.models import Confidence, Finding, Severity
from pyshield.rules.base import ASTContext, BaseRule

PRIVATE_KEY_PATTERN: re.Pattern[str] = re.compile(
    r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|ENCRYPTED\s+|PGP\s+)?PRIVATE\s+KEY(?:\s+BLOCK)?-----",
    re.IGNORECASE,
)


class PrivateKeyRule(BaseRule):
    """Detects private cryptographic key material embedded in source code."""

    rule_id = "PS202"
    title = "Private key material detected"
    description = (
        "Private cryptographic keys embedded directly in source code expose systems to "
        "impersonation, unauthorized decryption, and signature forgery."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    cwe = "CWE-312"
    remediation = (
        "Never store private keys in source code. Load private keys from secure key management "
        "services (AWS KMS, GCP KMS, Vault) or environment-protected files."
    )

    def check(self, context: ASTContext) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(context.tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value
                match = PRIVATE_KEY_PATTERN.search(val)
                if match:
                    line_offset = val[: match.start()].count("\n")
                    key_lineno = node.lineno + line_offset
                    findings.append(
                        self.create_finding(
                            context=context,
                            node=node,
                            message="Private key material appears to be embedded in source code.",
                            custom_snippet="-----BEGIN [REDACTED PRIVATE KEY]-----",
                            custom_line=key_lineno,
                        )
                    )

        return findings
