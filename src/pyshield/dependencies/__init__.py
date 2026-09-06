"""Dependency security analysis subsystem."""

from pyshield.dependencies.models import (
    Dependency,
    DependencySourceType,
    ProviderStatus,
    Vulnerability,
    VulnerabilityLookupResult,
)
from pyshield.dependencies.parser import (
    deduplicate_dependencies_for_vulnerability_scan,
    normalize_package_name,
    parse_dependency_file,
    parse_pyproject_toml,
    parse_requirements_txt,
    parse_uv_lock,
)
from pyshield.dependencies.providers.base import BaseVulnerabilityProvider
from pyshield.dependencies.providers.osv import OSVProvider
from pyshield.dependencies.scanner import DependencyScanner

__all__ = [
    "BaseVulnerabilityProvider",
    "Dependency",
    "DependencyScanner",
    "DependencySourceType",
    "OSVProvider",
    "ProviderStatus",
    "Vulnerability",
    "VulnerabilityLookupResult",
    "deduplicate_dependencies_for_vulnerability_scan",
    "normalize_package_name",
    "parse_dependency_file",
    "parse_pyproject_toml",
    "parse_requirements_txt",
    "parse_uv_lock",
]
