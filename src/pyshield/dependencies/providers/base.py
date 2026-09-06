"""Abstract base provider for vulnerability intelligence queries."""

from abc import ABC, abstractmethod

from pyshield.dependencies.models import VulnerabilityLookupResult


class BaseVulnerabilityProvider(ABC):
    """Abstract interface for querying vulnerability databases."""

    @abstractmethod
    def query_package(self, name: str, version: str) -> VulnerabilityLookupResult:
        """Query vulnerability database for a specific package name and exact version."""
        raise NotImplementedError

    @abstractmethod
    def query_batch(
        self, packages: list[tuple[str, str]]
    ) -> dict[tuple[str, str], VulnerabilityLookupResult]:
        """Query vulnerability database for multiple (package_name, version) pairs."""
        raise NotImplementedError
