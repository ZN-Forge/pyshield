"""Data models for dependency and vulnerability representation."""

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from pyshield.core.models import Severity


class DependencySourceType(StrEnum):
    """Supported dependency file source types."""

    REQUIREMENTS_TXT = "requirements.txt"
    PYPROJECT_TOML = "pyproject.toml"
    UV_LOCK = "uv.lock"


class Dependency(BaseModel):
    """Represents a declared or locked dependency package."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Normalized package name as per PEP 503")
    raw_name: str = Field(description="Original declared package name in source file")
    version: str | None = Field(
        default=None,
        description="Resolved exact version if known (e.g. from lockfile or exact pin)",
    )
    specifier: str | None = Field(
        default=None,
        description="Declared version constraint expression (e.g. '>=2.31', '==2.31.0')",
    )
    source_file: Path = Field(description="Path to the file where the dependency was declared")
    source_type: DependencySourceType = Field(description="Category of the source dependency file")
    line: int | None = Field(
        default=None,
        description="Line number in the source file where the dependency is declared (1-indexed)",
    )
    is_direct: bool = Field(
        default=True,
        description="Whether this dependency was directly specified by the user or root project",
    )


class Vulnerability(BaseModel):
    """Represents an identified security vulnerability in a package."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(description="Primary vulnerability identifier (e.g. GHSA-xxx, OSV-xxx)")
    summary: str = Field(description="Brief summary of the vulnerability")
    details: str | None = Field(default=None, description="Detailed vulnerability description")
    aliases: list[str] = Field(
        default_factory=list,
        description="Alternative identifiers such as CVEs or GHSAs",
    )
    fixed_version: str | None = Field(
        default=None,
        description="Version string where the vulnerability was remediated, if known",
    )
    severity: Severity = Field(
        default=Severity.HIGH,
        description="Assigned severity level for the vulnerability",
    )


class ProviderStatus(StrEnum):
    """Operational status of a vulnerability intelligence provider."""

    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    DISABLED = "DISABLED"


class VulnerabilityLookupResult(BaseModel):
    """Result of querying a vulnerability provider for a package."""

    model_config = ConfigDict(frozen=True)

    status: ProviderStatus = Field(description="Lookup status (AVAILABLE, UNAVAILABLE, DISABLED)")
    vulnerabilities: list[Vulnerability] = Field(
        default_factory=list,
        description="Identified vulnerabilities affecting the queried package and version",
    )
    error_message: str | None = Field(
        default=None,
        description="Diagnostic error message if lookup failed or was unavailable",
    )
