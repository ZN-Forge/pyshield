"""Scan Engine: discovers Python source files and orchestrates security analysis."""

import fnmatch
import time
from collections.abc import Iterator
from pathlib import Path

from pyshield.config.models import ScanConfig
from pyshield.core.analyzer import ASTAnalyzer
from pyshield.core.models import Finding, ScanResult, ScanSummary, Severity
from pyshield.core.registry import RuleRegistry


def should_exclude(path: Path, exclude_patterns: list[str]) -> bool:
    """Determine whether a given path matches any exclude pattern."""
    path_str = str(path).replace("\\", "/")
    parts = path.parts

    for pattern in exclude_patterns:
        # Check against path components (e.g. '.venv', '__pycache__')
        for part in parts:
            if fnmatch.fnmatch(part, pattern):
                return True
        # Check against full path string or glob
        if fnmatch.fnmatch(path_str, pattern) or fnmatch.fnmatch(path.name, pattern):
            return True

    return False


def discover_python_files(
    target_path: Path,
    exclude_patterns: list[str],
) -> list[Path]:
    """Discover all Python source files recursively, avoiding exclusions and symlink cycles."""
    if not target_path.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_path}")

    # If single file target
    if target_path.is_file():
        if target_path.suffix == ".py" and not should_exclude(target_path, exclude_patterns):
            return [target_path]
        return []

    discovered: list[Path] = []
    visited_dirs: set[str] = set()

    for root_dir, dirs, files in _safe_walk(target_path, visited_dirs):
        # Filter directories in-place to prevent traversing excluded dirs
        dirs[:] = [d for d in dirs if not should_exclude(root_dir / d, exclude_patterns)]

        for file_name in files:
            if file_name.endswith(".py"):
                file_path = root_dir / file_name
                if not should_exclude(file_path, exclude_patterns):
                    discovered.append(file_path)

    return sorted(discovered)


def _safe_walk(
    target_path: Path, visited_dirs: set[str]
) -> Iterator[tuple[Path, list[str], list[str]]]:
    """Walk directory tree while preventing symlink loops."""
    import os

    try:
        resolved_root = str(target_path.resolve())
        visited_dirs.add(resolved_root)
    except OSError:
        return

    for root, dirs, files in os.walk(target_path, followlinks=False):
        current_root_path = Path(root)
        try:
            visited_dirs.add(str(current_root_path.resolve()))
        except OSError:
            continue

        # Prevent circular symlink recursion
        filtered_dirs: list[str] = []
        for d in dirs:
            dir_path = current_root_path / d
            try:
                if dir_path.is_symlink():
                    resolved_target = str(dir_path.resolve())
                    if resolved_target in visited_dirs:
                        continue  # Skip symlink cycle
                    visited_dirs.add(resolved_target)
                filtered_dirs.append(d)
            except OSError:
                continue

        dirs[:] = filtered_dirs
        yield current_root_path, dirs, files


class ScanEngine:
    """Coordinates file discovery, AST analysis, and result aggregation."""

    def __init__(
        self,
        config: ScanConfig | None = None,
        registry: RuleRegistry | None = None,
    ) -> None:
        self.config = config or ScanConfig()
        self.registry = registry or RuleRegistry.create_default()

    def run(self) -> ScanResult:
        """Execute the configured scan across all target paths."""
        start_time = time.perf_counter()

        active_rules = self.registry.get_active(
            disabled_rules=self.config.disabled_rules,
            enabled_rules=self.config.enabled_rules,
        )
        analyzer = ASTAnalyzer(rules=active_rules)

        all_findings: list[Finding] = []
        all_diagnostics = []
        files_scanned = 0
        files_failed = 0

        # Collect files from all target paths
        target_files: list[Path] = []
        for target in self.config.target_paths:
            found = discover_python_files(target, self.config.exclude_patterns)
            target_files.extend(found)

        # Remove potential duplicates while preserving order
        unique_files = list(dict.fromkeys(target_files))

        for file_path in unique_files:
            findings, diagnostic = analyzer.analyze_file(
                file_path=file_path,
                max_file_size_bytes=self.config.max_file_size_bytes,
            )
            if diagnostic is not None:
                all_diagnostics.append(diagnostic)
                files_failed += 1
            else:
                files_scanned += 1
                all_findings.extend(findings)

        # Sort findings deterministically: file, line, col, rule_id
        all_findings.sort(key=lambda f: (str(f.file_path), f.line, f.column, f.rule_id))

        findings_count = {s: 0 for s in Severity}
        for finding in all_findings:
            findings_count[finding.severity] += 1

        duration = time.perf_counter() - start_time

        summary = ScanSummary(
            files_scanned=files_scanned,
            files_failed=files_failed,
            findings_count=findings_count,
            duration_seconds=round(duration, 3),
        )

        return ScanResult(
            findings=all_findings,
            diagnostics=all_diagnostics,
            summary=summary,
        )
