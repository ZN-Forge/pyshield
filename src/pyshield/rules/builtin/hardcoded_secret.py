"""PS201: Hardcoded secret / credential rule."""

import ast

from pyshield.core.models import Confidence, Finding, Severity
from pyshield.rules.base import ASTContext, BaseRule
from pyshield.rules.secrets_utils import (
    is_placeholder,
    is_suspicious_credential_name,
    mask_snippet,
    shannon_entropy,
)


class HardcodedSecretRule(BaseRule):
    """Detects likely hardcoded credentials assigned directly in source code."""

    rule_id = "PS201"
    title = "Hardcoded credential detected"
    description = (
        "Hardcoded credentials (passwords, secret keys, or authentication tokens) embedded "
        "directly in source code expose sensitive systems to unauthorized access and "
        "credential compromise."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe = "CWE-798"
    remediation = (
        "Retrieve credentials from environment variables (os.environ), secret management "
        "services (AWS Secrets Manager, HashiCorp Vault), or external secure configuration."
    )

    def _is_suspicious_value(self, val: str) -> bool:
        """Check if string value is long enough and not an obvious path, URL, or placeholder."""
        if len(val) < 8:
            return False
        if is_placeholder(val):
            return False
        # Skip obvious paths or URLs
        if val.startswith(("http://", "https://", "/", "file://")) or ":\\" in val or ":/" in val:
            return False
        return True

    def check(self, context: ASTContext) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(context.tree):
            # Case 1: Variable assignment (e.g. PASSWORD = "...")
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    target_name: str | None = None
                    if isinstance(target, ast.Name):
                        target_name = target.id
                    elif isinstance(target, ast.Attribute):
                        target_name = target.attr

                    if target_name and is_suspicious_credential_name(target_name):
                        if isinstance(node.value, ast.Constant) and isinstance(
                            node.value.value, str
                        ):
                            raw_val = node.value.value
                            if self._is_suspicious_value(raw_val):
                                entropy = shannon_entropy(raw_val)
                                conf = Confidence.HIGH if entropy >= 3.0 else Confidence.MEDIUM
                                line_no = getattr(node.value, "lineno", node.lineno)
                                raw_line = context.get_snippet(line_no) or ""
                                masked = mask_snippet(raw_line, raw_val)
                                findings.append(
                                    self.create_finding(
                                        context=context,
                                        node=node,
                                        message=(
                                            f"Possible hardcoded credential assigned to "
                                            f"'{target_name}'."
                                        ),
                                        custom_confidence=conf,
                                        custom_snippet=masked,
                                        custom_line=line_no,
                                    )
                                )

            # Case 2: Annotated assignment (e.g. API_KEY: str = "...")
            elif isinstance(node, ast.AnnAssign):
                target_name = None
                if isinstance(node.target, ast.Name):
                    target_name = node.target.id
                elif isinstance(node.target, ast.Attribute):
                    target_name = node.target.attr

                if (
                    target_name
                    and is_suspicious_credential_name(target_name)
                    and node.value is not None
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    raw_val = node.value.value
                    if self._is_suspicious_value(raw_val):
                        entropy = shannon_entropy(raw_val)
                        conf = Confidence.HIGH if entropy >= 3.0 else Confidence.MEDIUM
                        line_no = getattr(node.value, "lineno", node.lineno)
                        raw_line = context.get_snippet(line_no) or ""
                        masked = mask_snippet(raw_line, raw_val)
                        findings.append(
                            self.create_finding(
                                context=context,
                                node=node,
                                message=(
                                    f"Possible hardcoded credential assigned to '{target_name}'."
                                ),
                                custom_confidence=conf,
                                custom_snippet=masked,
                                custom_line=line_no,
                            )
                        )

            # Case 3: Dictionary keys (e.g. {"password": "..."})
            elif isinstance(node, ast.Dict):
                for key_node, val_node in zip(node.keys, node.values, strict=True):
                    if (
                        key_node is not None
                        and isinstance(key_node, ast.Constant)
                        and isinstance(key_node.value, str)
                    ):
                        key_name = key_node.value
                        if (
                            is_suspicious_credential_name(key_name)
                            and isinstance(val_node, ast.Constant)
                            and isinstance(val_node.value, str)
                        ):
                            raw_val = val_node.value
                            if self._is_suspicious_value(raw_val):
                                entropy = shannon_entropy(raw_val)
                                conf = Confidence.HIGH if entropy >= 3.0 else Confidence.MEDIUM
                                line_no = getattr(key_node, "lineno", node.lineno)
                                raw_line = context.get_snippet(line_no) or ""
                                masked = mask_snippet(raw_line, raw_val)
                                findings.append(
                                    self.create_finding(
                                        context=context,
                                        node=key_node,
                                        message=(
                                            f"Possible hardcoded credential in dictionary for "
                                            f"key '{key_name}'."
                                        ),
                                        custom_confidence=conf,
                                        custom_snippet=masked,
                                    )
                                )

        return findings
