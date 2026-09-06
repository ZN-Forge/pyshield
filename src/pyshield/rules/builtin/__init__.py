"""Built-in security rules for PyShield."""

from pyshield.rules.base import BaseRule
from pyshield.rules.builtin.api_token import ApiTokenRule
from pyshield.rules.builtin.dangerous_eval import DangerousEvalRule
from pyshield.rules.builtin.dangerous_exec import DangerousExecRule
from pyshield.rules.builtin.hardcoded_secret import HardcodedSecretRule
from pyshield.rules.builtin.insecure_crypto import InsecureCryptoRule
from pyshield.rules.builtin.insecure_random import InsecureRandomRule
from pyshield.rules.builtin.os_system import OsSystemRule
from pyshield.rules.builtin.private_key import PrivateKeyRule
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
]

__all__ = [
    "BUILTIN_RULES",
    "ApiTokenRule",
    "DangerousEvalRule",
    "DangerousExecRule",
    "HardcodedSecretRule",
    "InsecureCryptoRule",
    "InsecureRandomRule",
    "OsSystemRule",
    "PrivateKeyRule",
    "UnsafeSubprocessRule",
    "WeakHashRule",
]
