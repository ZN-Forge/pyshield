"""Built-in security rules for PyShield."""

from pyshield.rules.base import BaseRule
from pyshield.rules.builtin.api_token import ApiTokenRule
from pyshield.rules.builtin.dangerous_eval import DangerousEvalRule
from pyshield.rules.builtin.dangerous_exec import DangerousExecRule
from pyshield.rules.builtin.debug_mode import DebugModeRule
from pyshield.rules.builtin.hardcoded_secret import HardcodedSecretRule
from pyshield.rules.builtin.insecure_cookie import InsecureCookieRule
from pyshield.rules.builtin.insecure_crypto import InsecureCryptoRule
from pyshield.rules.builtin.insecure_host import InsecureHostRule
from pyshield.rules.builtin.insecure_random import InsecureRandomRule
from pyshield.rules.builtin.insecure_tls import InsecureTlsRule
from pyshield.rules.builtin.known_vulnerable_dep import KnownVulnerableDepRule
from pyshield.rules.builtin.os_system import OsSystemRule
from pyshield.rules.builtin.private_key import PrivateKeyRule
from pyshield.rules.builtin.unpinned_dep import UnpinnedDepRule
from pyshield.rules.builtin.unsafe_subprocess import UnsafeSubprocessRule
from pyshield.rules.builtin.weak_hash import WeakHashRule

BUILTIN_RULES: list[type[BaseRule]] = [
    # PS1xx: Execution / Injection
    DangerousEvalRule,
    DangerousExecRule,
    OsSystemRule,
    UnsafeSubprocessRule,
    # PS2xx: Secrets
    HardcodedSecretRule,
    PrivateKeyRule,
    ApiTokenRule,
    # PS3xx: Cryptography
    WeakHashRule,
    InsecureCryptoRule,
    InsecureRandomRule,
    # PS7xx: Configuration Security
    DebugModeRule,
    InsecureTlsRule,
    InsecureCookieRule,
    InsecureHostRule,
    # PS8xx: Dependency Security
    KnownVulnerableDepRule,
    UnpinnedDepRule,
]

__all__ = [
    "BUILTIN_RULES",
    "ApiTokenRule",
    "DangerousEvalRule",
    "DangerousExecRule",
    "DebugModeRule",
    "HardcodedSecretRule",
    "InsecureCookieRule",
    "InsecureCryptoRule",
    "InsecureHostRule",
    "InsecureRandomRule",
    "InsecureTlsRule",
    "KnownVulnerableDepRule",
    "OsSystemRule",
    "PrivateKeyRule",
    "UnpinnedDepRule",
    "UnsafeSubprocessRule",
    "WeakHashRule",
]
