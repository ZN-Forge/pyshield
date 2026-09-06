"""Configuration data models for PyShield."""

from pathlib import Path

from pydantic import BaseModel, Field

from pyshield.core.models import Severity

DEFAULT_EXCLUDES: list[str] = [
    ".git",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    "build",
    "dist",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "*.egg-info",
    ".eggs",
    ".tox",
    ".nox",
]


class ScanConfig(BaseModel):
    """Configuration options for a PyShield scan."""

    target_paths: list[Path] = Field(
        default_factory=lambda: [Path(".")],
        description="List of file or directory paths to analyze",
    )
    exclude_patterns: list[str] = Field(
        default_factory=lambda: list(DEFAULT_EXCLUDES),
        description="Glob patterns or directory names to exclude from analysis",
    )
    fail_on: Severity | None = Field(
        default=Severity.LOW,
        description="Minimum severity threshold that triggers a non-zero exit code",
    )
    max_file_size_bytes: int = Field(
        default=10 * 1024 * 1024,
        description="Maximum file size in bytes to inspect (default: 10MB)",
    )
    disabled_rules: set[str] = Field(
        default_factory=set,
        description="Set of rule IDs to disable during the scan",
    )
    enabled_rules: set[str] | None = Field(
        default=None,
        description="Explicit set of rule IDs to run (runs all registered if None)",
    )
    offline: bool = Field(
        default=False,
        description="Run in offline mode without querying external vulnerability databases",
    )
