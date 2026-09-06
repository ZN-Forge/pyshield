"""PS203: High-confidence API token / access token rule."""

import ast
import re

from pyshield.core.models import Confidence, Finding, Severity
from pyshield.rules.base import ASTContext, BaseRule
from pyshield.rules.secrets_utils import is_placeholder, mask_snippet

# Provider patterns: (Provider Name, Compiled Regex)
PROVIDER_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "AWS Access Key ID",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    ),
    (
        "GitHub Personal Access Token",
        re.compile(r"\b(ghp_[A-Za-z0-9]{36})\b"),
    ),
    (
        "GitHub Fine-Grained Personal Access Token",
        re.compile(r"\b(github_pat_[A-Za-z0-9_]{60,100})\b"),
    ),
    (
        "GitHub Access Token",
        re.compile(r"\b(gh[osr]_[A-Za-z0-9]{36})\b"),
    ),
    (
        "Slack Token",
        re.compile(r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b"),
    ),
    (
        "Google API Key",
        re.compile(r"\b(AIza[0-9A-Za-z\-_]{30,40})\b"),
    ),
    (
        "Stripe Secret Key",
        re.compile(r"\b((?:sk|rk)_(?:test|live)_[0-9a-zA-Z]{24,})\b"),
    ),
]


class ApiTokenRule(BaseRule):
    """Detects high-confidence structured API tokens and service keys."""

    rule_id = "PS203"
    title = "High-confidence API token detected"
    description = (
        "Hardcoded third-party API tokens, personal access tokens, or service credentials "
        "grant unauthorized access to cloud infrastructure, repositories, or external APIs."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    cwe = "CWE-798"
    remediation = (
        "Revoke the exposed token immediately. Store sensitive API keys in environment variables "
        "or secure secret stores (e.g. AWS Secrets Manager, Vault)."
    )

    def _is_token_placeholder(self, token: str) -> bool:
        """Verify token is not an obvious dummy or documentation example."""
        if is_placeholder(token):
            return True
        # Specific provider dummy checks
        upper_tok = token.upper()
        if "EXAMPLE" in upper_tok or "TESTING" in upper_tok:
            return True
        # Check if the secret suffix is dummy/repetitive (e.g. ghp_xxxx..., sk_test_xxxx...)
        suffix = token.rsplit("_", 1)[-1]
        if "xxxx" in suffix.lower() or "0000" in suffix or len(set(suffix)) <= 2:
            return True
        return False

    def check(self, context: ASTContext) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(context.tree):
            if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                continue

            content = node.value
            for provider_name, pattern in PROVIDER_PATTERNS:
                match = pattern.search(content)
                if match:
                    raw_token = match.group(1)
                    if self._is_token_placeholder(raw_token):
                        continue

                    line_offset = content[: match.start()].count("\n")
                    token_lineno = node.lineno + line_offset
                    raw_line = context.get_snippet(token_lineno) or ""
                    masked_snippet = mask_snippet(raw_line, raw_token)

                    findings.append(
                        self.create_finding(
                            context=context,
                            node=node,
                            message=f"High-confidence {provider_name} detected.",
                            custom_snippet=masked_snippet,
                            custom_line=token_lineno,
                        )
                    )
                    # Once a token pattern matches this node, avoid duplicate hits
                    break

        return findings
