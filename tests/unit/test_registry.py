"""Unit tests for RuleRegistry."""

import pytest

from pyshield.core.registry import RuleRegistry
from pyshield.rules.builtin.dangerous_eval import DangerousEvalRule
from pyshield.rules.builtin.dangerous_exec import DangerousExecRule
from pyshield.rules.builtin.os_system import OsSystemRule
from pyshield.rules.builtin.unsafe_subprocess import UnsafeSubprocessRule


class TestRuleRegistry:
    def test_default_registry_contains_builtin_rules(self) -> None:
        registry = RuleRegistry.create_default()
        assert len(registry) == 16
        expected_ids = {
            "PS101",
            "PS102",
            "PS103",
            "PS104",
            "PS201",
            "PS202",
            "PS203",
            "PS301",
            "PS302",
            "PS303",
            "PS701",
            "PS702",
            "PS703",
            "PS704",
            "PS801",
            "PS802",
        }
        for rid in expected_ids:
            assert rid in registry

    def test_register_rule_instance_and_class(self) -> None:
        registry = RuleRegistry()
        registry.register(DangerousEvalRule)
        registry.register(DangerousExecRule())
        assert len(registry) == 2
        assert registry.get("PS101") is not None
        assert registry.get("PS102") is not None

    def test_duplicate_registration_raises_error(self) -> None:
        registry = RuleRegistry()
        registry.register(DangerousEvalRule)
        with pytest.raises(ValueError, match="already registered"):
            registry.register(DangerousEvalRule)

    def test_duplicate_registration_with_overwrite(self) -> None:
        registry = RuleRegistry()
        registry.register(DangerousEvalRule)
        registry.register(DangerousEvalRule, overwrite=True)
        assert len(registry) == 1

    def test_get_nonexistent_rule(self) -> None:
        registry = RuleRegistry()
        assert registry.get("NONEXISTENT") is None

    def test_get_active_filters_disabled_and_enabled(self) -> None:
        registry = RuleRegistry()
        registry.register_all(
            [DangerousEvalRule, DangerousExecRule, OsSystemRule, UnsafeSubprocessRule]
        )

        # Test disabled
        active = registry.get_active(disabled_rules={"PS101", "PS103"})
        active_ids = {r.rule_id for r in active}
        assert active_ids == {"PS102", "PS104"}

        # Test enabled
        active_enabled = registry.get_active(enabled_rules={"PS101"})
        assert len(active_enabled) == 1
        assert active_enabled[0].rule_id == "PS101"
