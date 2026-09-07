"""Deterministic release validation script for PyShield.

Validates:
1. Release tag conforms strictly to 'vMAJOR.MINOR.PATCH'.
2. Release tag version matches pyproject.toml and src/pyshield/__init__.py.
3. Package identity conforms to:
   - distribution: pyshield-security
   - CLI command: pyshield
   - import name: pyshield
4. Optional: Distribution artifacts in dist/ match the release version.

Zero external dependencies: uses standard library only.
"""

import argparse
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

SEMVER_TAG_REGEX = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
EXPECTED_DIST_NAME = "pyshield-security"
EXPECTED_DIST_FILENAME_PREFIX = "pyshield_security"
EXPECTED_CLI_COMMAND = "pyshield"
EXPECTED_CLI_TARGET = "pyshield.cli.main:app"
EXPECTED_IMPORT_NAME = "pyshield"


def validate_tag_format(tag: str) -> str:
    """Validate that tag strictly conforms to 'vMAJOR.MINOR.PATCH'.

    Returns the cleaned version string without the leading 'v'.
    Raises ValueError if tag format is invalid.
    """
    match = SEMVER_TAG_REGEX.match(tag.strip())
    if not match:
        raise ValueError(
            f"Invalid release tag '{tag}'. Release tag must strictly follow "
            f"'vMAJOR.MINOR.PATCH' format (e.g. 'v0.3.0', 'v1.0.0'). "
            f"Tags without 'v' prefix, pre-releases, or partial versions are not permitted."
        )
    return f"{match.group(1)}.{match.group(2)}.{match.group(3)}"


def get_project_metadata(pyproject_path: Path) -> dict[str, Any]:
    """Load project metadata from pyproject.toml."""
    if not pyproject_path.exists():
        raise FileNotFoundError(f"pyproject.toml not found at: {pyproject_path}")
    try:
        content = pyproject_path.read_text(encoding="utf-8")
        return tomllib.loads(content)
    except Exception as err:
        raise ValueError(f"Failed to parse pyproject.toml: {err}") from err


def get_runtime_version(init_path: Path) -> str:
    """Extract __version__ from src/pyshield/__init__.py."""
    if not init_path.exists():
        raise FileNotFoundError(f"Package __init__.py not found at: {init_path}")
    content = init_path.read_text(encoding="utf-8")
    for line in content.splitlines():
        if line.startswith("__version__"):
            match = re.search(r'["\']([^"\']+)["\']', line)
            if match:
                return match.group(1).strip()
    raise ValueError(f"Could not find '__version__' assignment in {init_path}")


def validate_package_identity(pyproject_data: dict[str, Any]) -> None:
    """Verify distribution name, script command, and import package identity."""
    project = pyproject_data.get("project", {})
    dist_name = project.get("name")
    if dist_name != EXPECTED_DIST_NAME:
        raise ValueError(
            f"Unexpected distribution name in pyproject.toml: '{dist_name}'. "
            f"Must be '{EXPECTED_DIST_NAME}'."
        )

    scripts = project.get("scripts", {})
    if EXPECTED_CLI_COMMAND not in scripts:
        raise ValueError(
            f"CLI script '{EXPECTED_CLI_COMMAND}' missing from [project.scripts] in pyproject.toml."
        )
    if scripts[EXPECTED_CLI_COMMAND] != EXPECTED_CLI_TARGET:
        raise ValueError(
            f"CLI script target is '{scripts[EXPECTED_CLI_COMMAND]}', "
            f"expected '{EXPECTED_CLI_TARGET}'."
        )


def validate_version_match(tag_version: str, pyproject_version: str, init_version: str) -> None:
    """Verify that tag version, pyproject version, and __init__.py version match exactly."""
    errors: list[str] = []
    if tag_version != pyproject_version:
        errors.append(
            f"Tag version '{tag_version}' does not match "
            f"pyproject.toml version '{pyproject_version}'."
        )
    if tag_version != init_version:
        errors.append(
            f"Tag version '{tag_version}' does not match __init__.py version '{init_version}'."
        )
    if pyproject_version != init_version:
        errors.append(
            f"pyproject.toml version '{pyproject_version}' does not match "
            f"__init__.py version '{init_version}'."
        )

    if errors:
        msg = "Version mismatch detected:\n  " + "\n  ".join(errors)
        raise ValueError(msg)


def verify_dist_artifacts(dist_dir: Path, expected_version: str) -> None:
    """Verify that dist/ contains exactly the expected wheel and sdist for expected_version."""
    if not dist_dir.exists() or not dist_dir.is_dir():
        raise FileNotFoundError(f"Distribution directory '{dist_dir}' does not exist.")

    expected_wheel = f"{EXPECTED_DIST_FILENAME_PREFIX}-{expected_version}-py3-none-any.whl"
    expected_sdist = f"{EXPECTED_DIST_FILENAME_PREFIX}-{expected_version}.tar.gz"

    dist_files = [f for f in dist_dir.iterdir() if f.is_file() and not f.name.startswith(".")]

    found_wheel = any(f.name == expected_wheel for f in dist_files)
    found_sdist = any(f.name == expected_sdist for f in dist_files)

    errors: list[str] = []
    if not found_wheel:
        errors.append(f"Expected wheel artifact '{expected_wheel}' not found in {dist_dir}.")
    if not found_sdist:
        errors.append(f"Expected sdist artifact '{expected_sdist}' not found in {dist_dir}.")

    for f in dist_files:
        if f.name in (expected_wheel, expected_sdist):
            if f.stat().st_size == 0:
                errors.append(f"Distribution artifact '{f.name}' is empty (0 bytes).")
        else:
            errors.append(f"Unexpected artifact '{f.name}' found in {dist_dir}.")

    if errors:
        msg = "Distribution artifact validation failed:\n  " + "\n  ".join(errors)
        raise ValueError(msg)


def run_validation(
    tag: str,
    project_root: Path,
    verify_dist: bool = False,
) -> None:
    """Execute complete deterministic release validation."""
    print(f"==> Validating release tag: '{tag}'")
    cleaned_version = validate_tag_format(tag)
    print(f"    Semantic version extracted: '{cleaned_version}'")

    pyproject_path = project_root / "pyproject.toml"
    init_path = project_root / "src" / "pyshield" / "__init__.py"

    print("==> Checking pyproject.toml metadata & package identity...")
    metadata = get_project_metadata(pyproject_path)
    validate_package_identity(metadata)
    pyproject_version = metadata.get("project", {}).get("version", "")
    print(f"    Distribution name: '{metadata['project']['name']}'")
    print(f"    pyproject.toml version: '{pyproject_version}'")

    print("==> Checking runtime __init__.py version...")
    runtime_version = get_runtime_version(init_path)
    print(f"    Runtime version: '{runtime_version}'")

    print("==> Verifying version consistency...")
    validate_version_match(cleaned_version, pyproject_version, runtime_version)
    print("    Version check: MATCH (tag == pyproject == runtime)")

    if verify_dist:
        dist_dir = project_root / "dist"
        print(f"==> Verifying distribution artifacts in '{dist_dir}'...")
        verify_dist_artifacts(dist_dir, cleaned_version)
        print("    Distribution artifacts check: MATCH (wheel and sdist present and valid)")

    print("\n[SUCCESS] Release validation passed successfully!")


def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic release validation for PyShield.")
    parser.add_argument(
        "--tag",
        required=True,
        help="Git release tag to validate (e.g. 'v0.3.0').",
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Path to project root directory (default: current directory).",
    )
    parser.add_argument(
        "--verify-dist",
        action="store_true",
        help="Verify built distribution artifacts in dist/ directory.",
    )

    args = parser.parse_args()
    root_path = Path(args.root).resolve()

    try:
        run_validation(
            tag=args.tag,
            project_root=root_path,
            verify_dist=args.verify_dist,
        )
    except Exception as err:
        sys.stderr.write(f"\n[ERROR] Release validation failed: {err}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
