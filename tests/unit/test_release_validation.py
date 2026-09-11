"""Unit tests for scripts/validate_release.py release validation logic."""

import subprocess
import sys
from pathlib import Path

import pytest
from scripts.validate_release import (
    EXPECTED_CLI_COMMAND,
    EXPECTED_CLI_TARGET,
    EXPECTED_DIST_FILENAME_PREFIX,
    EXPECTED_DIST_NAME,
    get_project_metadata,
    get_runtime_version,
    validate_package_identity,
    validate_tag_format,
    validate_version_match,
    verify_dist_artifacts,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class TestValidateTagFormat:
    @pytest.mark.parametrize(
        ("tag", "expected_version"),
        [
            ("v0.1.0", "0.1.0"),
            ("v0.2.0", "0.2.0"),
            ("v0.3.0", "0.3.0"),
            ("v0.3.1", "0.3.1"),
            ("v1.0.0", "1.0.0"),
            ("v10.20.30", "10.20.30"),
        ],
    )
    def test_valid_semver_tags(self, tag: str, expected_version: str) -> None:
        assert validate_tag_format(tag) == expected_version

    @pytest.mark.parametrize(
        "invalid_tag",
        [
            "0.3.0",  # missing leading 'v'
            "release-0.3.0",  # non-v prefix
            "version-0.3.0",
            "v0.3",  # missing patch
            "v1",  # missing minor and patch
            "v0.3.0-rc1",  # pre-release not permitted
            "v0.3.0+build1",  # build metadata not permitted
            "v01.2.3",  # leading zero in non-zero number
            "v1.02.3",
            "v1.2.03",
            "v1.2.3.4",  # 4 components
            "foo",
            "",
            "   ",
        ],
    )
    def test_invalid_tag_formats_raise_error(self, invalid_tag: str) -> None:
        with pytest.raises(ValueError, match="Invalid release tag"):
            validate_tag_format(invalid_tag)


class TestProjectMetadataAndIdentity:
    def test_get_project_metadata_success(self, tmp_path: Path) -> None:
        toml_content = """
[project]
name = "pyshield-security"
version = "0.2.0"
[project.scripts]
pyshield = "pyshield.cli.main:app"
"""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(toml_content, encoding="utf-8")
        data = get_project_metadata(pyproject)
        assert data["project"]["name"] == "pyshield-security"
        assert data["project"]["version"] == "0.2.0"

    def test_get_project_metadata_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            get_project_metadata(tmp_path / "nonexistent.toml")

    def test_validate_package_identity_success(self) -> None:
        data = {
            "project": {
                "name": EXPECTED_DIST_NAME,
                "scripts": {EXPECTED_CLI_COMMAND: EXPECTED_CLI_TARGET},
            }
        }
        validate_package_identity(data)

    def test_validate_package_identity_wrong_name_raises(self) -> None:
        data = {
            "project": {
                "name": "pyshield",  # Should be pyshield-security
                "scripts": {EXPECTED_CLI_COMMAND: EXPECTED_CLI_TARGET},
            }
        }
        with pytest.raises(ValueError, match="Unexpected distribution name"):
            validate_package_identity(data)

    def test_validate_package_identity_missing_script_raises(self) -> None:
        data = {
            "project": {
                "name": EXPECTED_DIST_NAME,
                "scripts": {},
            }
        }
        with pytest.raises(ValueError, match="missing from"):
            validate_package_identity(data)

    def test_validate_package_identity_wrong_target_raises(self) -> None:
        data = {
            "project": {
                "name": EXPECTED_DIST_NAME,
                "scripts": {EXPECTED_CLI_COMMAND: "wrong.module:app"},
            }
        }
        with pytest.raises(ValueError, match="CLI script target is"):
            validate_package_identity(data)


class TestRuntimeVersion:
    def test_get_runtime_version_success(self, tmp_path: Path) -> None:
        init_py = tmp_path / "__init__.py"
        init_py.write_text('__version__ = "0.2.0"\n', encoding="utf-8")
        assert get_runtime_version(init_py) == "0.2.0"

    def test_get_runtime_version_single_quotes(self, tmp_path: Path) -> None:
        init_py = tmp_path / "__init__.py"
        init_py.write_text("__version__ = '1.0.0'\n", encoding="utf-8")
        assert get_runtime_version(init_py) == "1.0.0"

    def test_get_runtime_version_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            get_runtime_version(tmp_path / "nonexistent.py")

    def test_get_runtime_version_missing_assignment_raises(self, tmp_path: Path) -> None:
        init_py = tmp_path / "__init__.py"
        init_py.write_text("# No version here\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Could not find '__version__'"):
            get_runtime_version(init_py)


class TestVersionMatch:
    def test_version_match_identical_passes(self) -> None:
        validate_version_match("0.3.0", "0.3.0", "0.3.0")

    def test_version_match_pyproject_mismatch_raises(self) -> None:
        with pytest.raises(ValueError, match="Version mismatch detected") as exc_info:
            validate_version_match("0.3.0", "0.2.0", "0.3.0")
        assert "pyproject.toml version '0.2.0'" in str(exc_info.value)

    def test_version_match_init_mismatch_raises(self) -> None:
        with pytest.raises(ValueError, match="Version mismatch detected") as exc_info:
            validate_version_match("0.3.0", "0.3.0", "0.2.0")
        assert "__init__.py version '0.2.0'" in str(exc_info.value)

    def test_version_match_tag_mismatch_raises(self) -> None:
        with pytest.raises(ValueError, match="Version mismatch detected") as exc_info:
            validate_version_match("0.4.0", "0.3.0", "0.3.0")
        assert "Tag version '0.4.0'" in str(exc_info.value)


class TestVerifyDistArtifacts:
    def test_verify_dist_artifacts_success(self, tmp_path: Path) -> None:
        dist_dir = tmp_path / "dist"
        dist_dir.mkdir()
        wheel = dist_dir / f"{EXPECTED_DIST_FILENAME_PREFIX}-0.3.0-py3-none-any.whl"
        sdist = dist_dir / f"{EXPECTED_DIST_FILENAME_PREFIX}-0.3.0.tar.gz"
        wheel.write_bytes(b"non-empty wheel content")
        sdist.write_bytes(b"non-empty sdist content")

        verify_dist_artifacts(dist_dir, "0.3.0")

    def test_verify_dist_artifacts_missing_dir_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            verify_dist_artifacts(tmp_path / "nonexistent", "0.3.0")

    def test_verify_dist_artifacts_missing_wheel_raises(self, tmp_path: Path) -> None:
        dist_dir = tmp_path / "dist"
        dist_dir.mkdir()
        sdist = dist_dir / f"{EXPECTED_DIST_FILENAME_PREFIX}-0.3.0.tar.gz"
        sdist.write_bytes(b"sdist content")

        with pytest.raises(ValueError, match="Expected wheel artifact"):
            verify_dist_artifacts(dist_dir, "0.3.0")

    def test_verify_dist_artifacts_missing_sdist_raises(self, tmp_path: Path) -> None:
        dist_dir = tmp_path / "dist"
        dist_dir.mkdir()
        wheel = dist_dir / f"{EXPECTED_DIST_FILENAME_PREFIX}-0.3.0-py3-none-any.whl"
        wheel.write_bytes(b"wheel content")

        with pytest.raises(ValueError, match="Expected sdist artifact"):
            verify_dist_artifacts(dist_dir, "0.3.0")

    def test_verify_dist_artifacts_empty_file_raises(self, tmp_path: Path) -> None:
        dist_dir = tmp_path / "dist"
        dist_dir.mkdir()
        wheel = dist_dir / f"{EXPECTED_DIST_FILENAME_PREFIX}-0.3.0-py3-none-any.whl"
        sdist = dist_dir / f"{EXPECTED_DIST_FILENAME_PREFIX}-0.3.0.tar.gz"
        wheel.write_bytes(b"")  # empty!
        sdist.write_bytes(b"sdist content")

        with pytest.raises(ValueError, match="is empty"):
            verify_dist_artifacts(dist_dir, "0.3.0")

    def test_verify_dist_artifacts_unexpected_artifact_raises(self, tmp_path: Path) -> None:
        dist_dir = tmp_path / "dist"
        dist_dir.mkdir()
        wheel = dist_dir / f"{EXPECTED_DIST_FILENAME_PREFIX}-0.3.0-py3-none-any.whl"
        sdist = dist_dir / f"{EXPECTED_DIST_FILENAME_PREFIX}-0.3.0.tar.gz"
        old_wheel = dist_dir / f"{EXPECTED_DIST_FILENAME_PREFIX}-0.2.0-py3-none-any.whl"
        wheel.write_bytes(b"wheel content")
        sdist.write_bytes(b"sdist content")
        old_wheel.write_bytes(b"old wheel")

        with pytest.raises(ValueError, match="Unexpected artifact"):
            verify_dist_artifacts(dist_dir, "0.3.0")


class TestValidateReleaseCLI:
    def test_cli_on_current_repo_v0_3_0(self) -> None:
        cmd = [
            sys.executable,
            str(PROJECT_ROOT / "scripts" / "validate_release.py"),
            "--tag",
            "v0.3.0",
            "--root",
            str(PROJECT_ROOT),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0
        assert "Release validation passed successfully!" in res.stdout

    def test_cli_on_current_repo_mismatched_tag(self) -> None:
        cmd = [
            sys.executable,
            str(PROJECT_ROOT / "scripts" / "validate_release.py"),
            "--tag",
            "v0.99.0",
            "--root",
            str(PROJECT_ROOT),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 1
        assert "Version mismatch detected" in res.stderr
