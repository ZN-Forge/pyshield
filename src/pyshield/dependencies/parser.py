"""Deterministic dependency parsers for requirements.txt, pyproject.toml, and uv.lock."""

import re
import tomllib
from pathlib import Path

from pyshield.dependencies.models import Dependency, DependencySourceType

# Regex for PEP 508 / pip requirements lines
# Groups: 1: name, 2: extras (optional), 3: version specifier (optional), 4: marker (optional)
DEP_LINE_REGEX = re.compile(
    r"^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?:\[([^\]]*)\])?"
    r"\s*([~=<>!]=?[^;\s#]+(?:\s*,\s*[~=<>!]=?[^;\s#]+)*)?"
    r"(?:\s*;\s*([^#]*))?"
)

EXACT_VERSION_REGEX = re.compile(r"^===?\s*([A-Za-z0-9.+!-]+)$")


def normalize_package_name(name: str) -> str:
    """Normalize package name according to PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


def extract_exact_version(specifier: str | None) -> str | None:
    """Extract exact version string if specifier represents an exact pin (== or ===)."""
    if not specifier:
        return None
    cleaned = specifier.strip()
    match = EXACT_VERSION_REGEX.match(cleaned)
    if match:
        return match.group(1).strip()
    return None


def parse_dependency_string(
    dep_str: str,
    source_file: Path,
    source_type: DependencySourceType,
    line: int | None = None,
    is_direct: bool = True,
) -> Dependency | None:
    """Parse a single dependency string (e.g. 'requests>=2.31.0') into a Dependency model."""
    raw = dep_str.strip()
    if not raw or raw.startswith("#"):
        return None

    # Strip inline comments
    if " #" in raw:
        raw = raw.split(" #", 1)[0].strip()

    # Skip pip options and flags
    if raw.startswith(("-r", "-i", "-f", "-e", "--")):
        return None

    match = DEP_LINE_REGEX.match(raw)
    if not match:
        return None

    raw_name = match.group(1)
    specifier = match.group(3)
    cleaned_specifier = specifier.strip() if specifier else None
    version = extract_exact_version(cleaned_specifier)

    return Dependency(
        name=normalize_package_name(raw_name),
        raw_name=raw_name,
        version=version,
        specifier=cleaned_specifier,
        source_file=source_file,
        source_type=source_type,
        line=line,
        is_direct=is_direct,
    )


def parse_requirements_txt(file_path: Path) -> list[Dependency]:
    """Parse dependencies from a requirements.txt file."""
    dependencies: list[Dependency] = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    for idx, line in enumerate(content.splitlines(), start=1):
        dep = parse_dependency_string(
            dep_str=line,
            source_file=file_path,
            source_type=DependencySourceType.REQUIREMENTS_TXT,
            line=idx,
            is_direct=True,
        )
        if dep is not None:
            dependencies.append(dep)

    return dependencies


def _find_line_number(lines: list[str], target: str) -> int | None:
    """Helper to locate line number containing target string."""
    target_clean = target.strip()
    for idx, line in enumerate(lines, start=1):
        if target_clean in line:
            return idx
    return None


def parse_pyproject_toml(file_path: Path) -> list[Dependency]:
    """Parse dependencies from pyproject.toml supporting PEP 621 and dependency-groups."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        data = tomllib.loads(content)
    except (OSError, tomllib.TOMLDecodeError):
        return []

    lines = content.splitlines()
    dependencies: list[Dependency] = []

    project_data = data.get("project", {})

    # 1. Standard PEP 621 project.dependencies
    standard_deps = project_data.get("dependencies", [])
    if isinstance(standard_deps, list):
        for item in standard_deps:
            if isinstance(item, str):
                line_no = _find_line_number(lines, item)
                dep = parse_dependency_string(
                    dep_str=item,
                    source_file=file_path,
                    source_type=DependencySourceType.PYPROJECT_TOML,
                    line=line_no,
                    is_direct=True,
                )
                if dep:
                    dependencies.append(dep)

    # 2. PEP 621 project.optional-dependencies
    optional_deps = project_data.get("optional-dependencies", {})
    if isinstance(optional_deps, dict):
        for group_deps in optional_deps.values():
            if isinstance(group_deps, list):
                for item in group_deps:
                    if isinstance(item, str):
                        line_no = _find_line_number(lines, item)
                        dep = parse_dependency_string(
                            dep_str=item,
                            source_file=file_path,
                            source_type=DependencySourceType.PYPROJECT_TOML,
                            line=line_no,
                            is_direct=True,
                        )
                        if dep:
                            dependencies.append(dep)

    # 3. Standard dependency-groups (PEP 735)
    dep_groups = data.get("dependency-groups", {})
    if isinstance(dep_groups, dict):
        for group_items in dep_groups.values():
            if isinstance(group_items, list):
                for item in group_items:
                    if isinstance(item, str):
                        line_no = _find_line_number(lines, item)
                        dep = parse_dependency_string(
                            dep_str=item,
                            source_file=file_path,
                            source_type=DependencySourceType.PYPROJECT_TOML,
                            line=line_no,
                            is_direct=True,
                        )
                        if dep:
                            dependencies.append(dep)

    return dependencies


def parse_uv_lock(file_path: Path) -> list[Dependency]:
    """Parse resolved dependencies from uv.lock."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        data = tomllib.loads(content)
    except (OSError, tomllib.TOMLDecodeError):
        return []

    lines = content.splitlines()
    dependencies: list[Dependency] = []

    packages = data.get("package", [])
    if not isinstance(packages, list):
        return []

    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        raw_name = pkg.get("name")
        version = pkg.get("version")
        if not raw_name or not isinstance(raw_name, str):
            continue

        str_version = str(version) if version is not None else None
        # Locate line in uv.lock
        target_marker = f'name = "{raw_name}"'
        line_no = _find_line_number(lines, target_marker)

        dependencies.append(
            Dependency(
                name=normalize_package_name(raw_name),
                raw_name=raw_name,
                version=str_version,
                specifier=f"=={str_version}" if str_version else None,
                source_file=file_path,
                source_type=DependencySourceType.UV_LOCK,
                line=line_no,
                is_direct=True,
            )
        )

    return dependencies


def parse_dependency_file(file_path: Path) -> list[Dependency]:
    """Dispatch file parsing based on filename conventions."""
    name = file_path.name.lower()
    if name == "uv.lock":
        return parse_uv_lock(file_path)
    if name == "pyproject.toml":
        return parse_pyproject_toml(file_path)
    if name.startswith("requirements") and name.endswith(".txt"):
        return parse_requirements_txt(file_path)
    return []


def deduplicate_dependencies_for_vulnerability_scan(
    dependencies: list[Dependency],
) -> list[Dependency]:
    """Normalize and deduplicate dependencies across sources.

    Prioritizes sources with exact resolved versions (uv.lock > pinned == > unpinned)
    to prevent duplicate OSV queries and duplicate vulnerability findings.
    """
    grouped: dict[str, list[Dependency]] = {}
    for dep in dependencies:
        grouped.setdefault(dep.name, []).append(dep)

    deduplicated: list[Dependency] = []
    for _name, deps in grouped.items():
        # Priority 1: UV_LOCK with a resolved version
        lock_dep = next(
            (
                d
                for d in deps
                if d.source_type == DependencySourceType.UV_LOCK and d.version is not None
            ),
            None,
        )
        if lock_dep:
            deduplicated.append(lock_dep)
            continue

        # Priority 2: Any dependency with an exact pinned version
        pinned_dep = next((d for d in deps if d.version is not None), None)
        if pinned_dep:
            deduplicated.append(pinned_dep)
            continue

        # Priority 3: Fall back to first declared occurrence
        deduplicated.append(deps[0])

    return deduplicated
