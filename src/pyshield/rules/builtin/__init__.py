"""Built-in security rules for PyShield."""

from pyshield.rules.base import BaseRule
from pyshield.rules.builtin.dangerous_eval import DangerousEvalRule
from pyshield.rules.builtin.dangerous_exec import DangerousExecRule
from pyshield.rules.builtin.os_system import OsSystemRule
from pyshield.rules.builtin.unsafe_subprocess import UnsafeSubprocessRule

BUILTIN_RULES: list[type[BaseRule]] = [
    DangerousEvalRule,
    DangerousExecRule,
    OsSystemRule,
    UnsafeSubprocessRule,
]

__all__ = [
    "BUILTIN_RULES",
    "DangerousEvalRule",
    "DangerousExecRule",
    "OsSystemRule",
    "UnsafeSubprocessRule",
]
