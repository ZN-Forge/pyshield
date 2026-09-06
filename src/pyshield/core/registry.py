"""Rule registry for managing and querying PyShield security rules."""

from collections.abc import Iterable

from pyshield.rules.base import BaseRule
from pyshield.rules.builtin import BUILTIN_RULES


class RuleRegistry:
    """Registry managing available PyShield security rules."""

    def __init__(self) -> None:
        self._rules: dict[str, BaseRule] = {}

    def register(self, rule: BaseRule | type[BaseRule], overwrite: bool = False) -> None:
        """Register a new rule instance or class in the registry."""
        rule_instance = rule() if isinstance(rule, type) else rule
        rule_id = rule_instance.rule_id

        if rule_id in self._rules and not overwrite:
            raise ValueError(f"Rule with ID '{rule_id}' is already registered.")

        self._rules[rule_id] = rule_instance

    def register_all(
        self, rules: Iterable[BaseRule | type[BaseRule]], overwrite: bool = False
    ) -> None:
        """Register multiple rules."""
        for r in rules:
            self.register(r, overwrite=overwrite)

    def get(self, rule_id: str) -> BaseRule | None:
        """Retrieve a rule by its ID, or None if not found."""
        return self._rules.get(rule_id)

    def get_all(self) -> list[BaseRule]:
        """Return all registered rule instances sorted by rule_id."""
        return sorted(self._rules.values(), key=lambda r: r.rule_id)

    def get_active(
        self,
        disabled_rules: set[str] | None = None,
        enabled_rules: set[str] | None = None,
    ) -> list[BaseRule]:
        """Return active rules considering enabled and disabled rule sets."""
        disabled = disabled_rules or set()
        rules = self.get_all()

        if enabled_rules is not None:
            rules = [r for r in rules if r.rule_id in enabled_rules]

        return [r for r in rules if r.rule_id not in disabled]

    def __len__(self) -> int:
        return len(self._rules)

    def __contains__(self, rule_id: str) -> bool:
        return rule_id in self._rules

    @classmethod
    def create_default(cls) -> "RuleRegistry":
        """Instantiate a registry prepopulated with all built-in rules."""
        registry = cls()
        registry.register_all(BUILTIN_RULES)
        return registry
