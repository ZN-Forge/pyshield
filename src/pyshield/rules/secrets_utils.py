"""Utilities for deterministic secret detection, placeholder filtering, and masking."""

import math
import re

# Obvious placeholder exact words (case-insensitive)
COMMON_PLACEHOLDERS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pass",
        "changeme",
        "change-me",
        "change_me",
        "admin",
        "secret",
        "example",
        "sample",
        "test",
        "testing",
        "dummy",
        "placeholder",
        "your-api-key",
        "your_api_key",
        "your-key",
        "your_key",
        "your-token",
        "your_token",
        "your-secret",
        "your_secret",
        "secret-here",
        "secret_here",
        "replace-me",
        "replace_me",
        "my-secret",
        "my_secret",
        "none",
        "null",
        "true",
        "false",
        "default",
        "root",
        "guest",
        "todo",
        "xxx",
        "yyyy",
        "123456",
        "12345678",
        "qwerty",
        "temp",
        "foobar",
    }
)

# Suspicious credential variable / key name patterns
CREDENTIAL_NAME_PATTERN: re.Pattern[str] = re.compile(
    r"^(?=.*(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret|private[_-]?key))"
    r"(?!.*(public[_-]?key|key[_-]?id|tokenizer|keyboard|keyword|token[_-]?type|secret[_-]?name|secret[_-]?file|password[_-]?prompt)).*$",
    re.IGNORECASE,
)

# Placeholder regex patterns
TEMPLATE_PATTERN: re.Pattern[str] = re.compile(
    r"^(\s*<[^>]+>\s*|\$\{[^}]+\}|\{\{[^}]+\}|\.\.\.|xxx+|your[-_][a-z0-9_-]+|example[-_][a-z0-9_-]+)$",
    re.IGNORECASE,
)


def is_placeholder(value: str) -> bool:
    """Return True if value matches known obvious placeholder patterns."""
    val_clean = value.strip()
    if not val_clean:
        return True

    val_lower = val_clean.lower()
    if val_lower in COMMON_PLACEHOLDERS:
        return True

    # Bracketed templates: <...>, ${...}, {{...}}
    if val_clean.startswith("<") and val_clean.endswith(">"):
        return True
    if val_clean.startswith("${") and val_clean.endswith("}"):
        return True
    if val_clean.startswith("{{") and val_clean.endswith("}}"):
        return True

    if TEMPLATE_PATTERN.match(val_clean):
        return True

    # Repetitive dummy patterns
    if "xxxx" in val_lower or "00000" in val_clean or "...." in val_clean:
        return True

    # Single repeated character (e.g. 'xxxxxxxxx', '00000000', '********')
    if len(val_clean) > 3 and len(set(val_clean)) <= 2:
        return True

    # Common prefixes indicating mock or placeholder
    if val_lower.startswith(("example-", "example_", "dummy-", "dummy_", "test-", "test_")):
        return True

    return False


def mask_secret(secret: str, prefix_len: int = 4, mask_char: str = "*") -> str:
    """Mask secret value so that actual sensitive text is never exposed."""
    if len(secret) <= 8:
        return mask_char * max(len(secret), 8)

    prefix = secret[:prefix_len]
    masked_part = mask_char * (len(secret) - prefix_len)
    return f"{prefix}{masked_part}"


def mask_snippet(raw_line: str, secret: str) -> str:
    """Return raw_line with all occurrences of secret replaced by a masked representation."""
    if not raw_line or not secret:
        return raw_line

    masked = mask_secret(secret)
    if secret in raw_line:
        return raw_line.replace(secret, masked)

    # If secret is multiline or has trailing newlines, replace line-by-line
    result = raw_line
    for line in secret.splitlines():
        line_clean = line.strip()
        if len(line_clean) >= 4 and line_clean in result:
            result = result.replace(line_clean, mask_secret(line_clean))

    if result != raw_line:
        return result

    # Fallback: if secret had escapes differing between AST and source code,
    # mask any long quoted literal on this line to prevent secret leakage.
    def _mask_quoted(m: re.Match[str]) -> str:
        quote = m.group(1)
        content = m.group(2)
        if len(content) >= 6:
            return f"{quote}{mask_secret(content)}{quote}"
        return m.group(0)

    return re.sub(r"(['\"]{1,3})((?:\\.|(?!\1).)+)\1", _mask_quoted, raw_line)


def shannon_entropy(text: str) -> float:
    """Calculate the Shannon entropy of a string (bits per character)."""
    if not text:
        return 0.0

    freq: dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def is_suspicious_credential_name(name: str) -> bool:
    """Return True if an identifier or dictionary key name suggests a credential."""
    return bool(CREDENTIAL_NAME_PATTERN.match(name))
