"""Dependency security scanner orchestrating parsers, provider queries, and rules."""

from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from pyshield.core.models import FileDiagnostic, Finding
from pyshield.dependencies.models import (
    Dependency,
    ProviderStatus,
)
from pyshield.dependencies.parser import (
    deduplicate_dependencies_for_vulnerability_scan,
    parse_dependency_file,
)
from pyshield.dependencies.providers.base import BaseVulnerabilityProvider
from pyshield.dependencies.providers.osv import OSVProvider
from pyshield.rules.base import BaseRule

if TYPE_CHECKING:
    from pyshield.rules.builtin.known_vulnerable_dep import KnownVulnerableDepRule
    from pyshield.rules.builtin.unpinned_dep import UnpinnedDepRule


class DependencyScanner:
    """Coordinates dependency discovery, parsing, vulnerability intelligence, and rules."""

    def __init__(
        self,
        rules: list[BaseRule],
        provider: BaseVulnerabilityProvider | None = None,
        offline: bool = False,
    ) -> None:
        self.rules = rules
        self.provider = provider or OSVProvider()
        self.offline = offline

        rule_801 = next((r for r in rules if getattr(r, "rule_id", None) == "PS801"), None)
        rule_802 = next((r for r in rules if getattr(r, "rule_id", None) == "PS802"), None)
        self.ps801_rule: KnownVulnerableDepRule | None = cast(Any, rule_801)
        self.ps802_rule: UnpinnedDepRule | None = cast(Any, rule_802)

    def scan_files(self, files: list[Path]) -> tuple[list[Finding], list[FileDiagnostic]]:
        """Scan a set of dependency files for vulnerability and pinning security issues."""
        if not files:
            return [], []

        findings: list[Finding] = []
        diagnostics: list[FileDiagnostic] = []

        all_parsed_deps: list[Dependency] = []
        file_lines_cache: dict[Path, list[str]] = {}

        # 1. Parse all dependency files
        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                file_lines_cache[file_path] = content.splitlines()
            except OSError as err:
                diagnostics.append(
                    FileDiagnostic(
                        file_path=file_path,
                        error_type="ReadError",
                        message=f"Failed to read dependency file: {err}",
                    )
                )
                continue

            deps = parse_dependency_file(file_path)
            all_parsed_deps.extend(deps)

        # 2. Evaluate PS802: Unpinned dependencies
        if self.ps802_rule is not None:
            for dep in all_parsed_deps:
                snippet = self._get_snippet(dep, file_lines_cache)
                finding = self.ps802_rule.check_dependency(dep, snippet=snippet)
                if finding:
                    findings.append(finding)

        # 3. Evaluate PS801: Known vulnerable dependencies
        if self.ps801_rule is not None:
            if self.offline:
                for file_path in files:
                    diagnostics.append(
                        FileDiagnostic(
                            file_path=file_path,
                            error_type="OfflineMode",
                            message="Dependency vulnerability lookup skipped in offline mode.",
                        )
                    )
            else:
                # Deduplicate across files so each package is queried only once,
                # preferring uv.lock for resolved exact versions
                deduped = deduplicate_dependencies_for_vulnerability_scan(all_parsed_deps)
                versioned_deps = [d for d in deduped if d.version is not None]

                if versioned_deps:
                    queries = [(d.name, d.version) for d in versioned_deps if d.version]
                    query_results = self.provider.query_batch(queries)

                    seen_unavail_files: set[Path] = set()
                    for dep in versioned_deps:
                        if not dep.version:
                            continue
                        key = (dep.name, dep.version)
                        lookup_res = query_results.get(key)
                        if not lookup_res:
                            continue

                        if lookup_res.status == ProviderStatus.UNAVAILABLE:
                            if dep.source_file not in seen_unavail_files:
                                seen_unavail_files.add(dep.source_file)
                                diagnostics.append(
                                    FileDiagnostic(
                                        file_path=dep.source_file,
                                        error_type="VulnerabilityLookupUnavailable",
                                        message=(
                                            lookup_res.error_message
                                            or "Dependency vulnerability lookup unavailable"
                                        ),
                                    )
                                )
                        elif lookup_res.status == ProviderStatus.AVAILABLE:
                            snippet = self._get_snippet(dep, file_lines_cache)
                            dep_findings = self.ps801_rule.check_dependency(
                                dependency=dep,
                                lookup_result=lookup_res,
                                snippet=snippet,
                            )
                            findings.extend(dep_findings)

        return findings, diagnostics

    @staticmethod
    def _get_snippet(dep: Dependency, file_lines_cache: dict[Path, list[str]]) -> str | None:
        """Extract source line snippet for a dependency if available."""
        lines = file_lines_cache.get(dep.source_file)
        if lines and dep.line and 1 <= dep.line <= len(lines):
            return lines[dep.line - 1].strip()
        if dep.version:
            return f"{dep.raw_name}=={dep.version}"
        return dep.raw_name
