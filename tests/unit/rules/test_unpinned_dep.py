"""Unit tests for PS802: UnpinnedDepRule."""

from pathlib import Path

from pyshield.core.models import Severity
from pyshield.dependencies.models import Dependency, DependencySourceType
from pyshield.rules.builtin.unpinned_dep import UnpinnedDepRule


class TestUnpinnedDepRule:
    def setup_method(self) -> None:
        self.rule = UnpinnedDepRule()

    def test_unpinned_dependency_requirements_txt(self) -> None:
        dep = Dependency(
            name="flask",
            raw_name="flask",
            version=None,
            specifier=None,
            source_file=Path("requirements.txt"),
            source_type=DependencySourceType.REQUIREMENTS_TXT,
            line=2,
        )

        finding = self.rule.check_dependency(dep, snippet="flask")
        assert finding is not None
        assert finding.rule_id == "PS802"
        assert finding.severity == Severity.MEDIUM
        assert finding.cwe == "CWE-1104"
        assert finding.line == 2
        assert "flask" in finding.message

    def test_unpinned_dependency_pyproject_toml(self) -> None:
        dep = Dependency(
            name="django",
            raw_name="Django",
            version=None,
            specifier=None,
            source_file=Path("pyproject.toml"),
            source_type=DependencySourceType.PYPROJECT_TOML,
            line=10,
        )

        finding = self.rule.check_dependency(dep, snippet='"Django",')
        assert finding is not None
        assert finding.rule_id == "PS802"

    def test_exact_pinned_safe(self) -> None:
        dep = Dependency(
            name="requests",
            raw_name="requests",
            version="2.31.0",
            specifier="==2.31.0",
            source_file=Path("requirements.txt"),
            source_type=DependencySourceType.REQUIREMENTS_TXT,
            line=1,
        )
        assert self.rule.check_dependency(dep) is None

    def test_minimum_version_pinned_safe(self) -> None:
        dep = Dependency(
            name="requests",
            raw_name="requests",
            version=None,
            specifier=">=2.31",
            source_file=Path("requirements.txt"),
            source_type=DependencySourceType.REQUIREMENTS_TXT,
            line=1,
        )
        assert self.rule.check_dependency(dep) is None

    def test_compatible_version_pinned_safe(self) -> None:
        dep = Dependency(
            name="requests",
            raw_name="requests",
            version=None,
            specifier="~=2.31",
            source_file=Path("requirements.txt"),
            source_type=DependencySourceType.REQUIREMENTS_TXT,
            line=1,
        )
        assert self.rule.check_dependency(dep) is None

    def test_upper_bound_version_pinned_safe(self) -> None:
        dep = Dependency(
            name="requests",
            raw_name="requests",
            version=None,
            specifier="<3",
            source_file=Path("requirements.txt"),
            source_type=DependencySourceType.REQUIREMENTS_TXT,
            line=1,
        )
        assert self.rule.check_dependency(dep) is None

    def test_uv_lock_always_exempt(self) -> None:
        dep = Dependency(
            name="flask",
            raw_name="flask",
            version="3.0.0",
            specifier="==3.0.0",
            source_file=Path("uv.lock"),
            source_type=DependencySourceType.UV_LOCK,
            line=15,
        )
        # Even if specifier is None or empty in lockfile
        dep_unpinned_repr = Dependency(
            name="flask",
            raw_name="flask",
            version=None,
            specifier=None,
            source_file=Path("uv.lock"),
            source_type=DependencySourceType.UV_LOCK,
            line=15,
        )
        assert self.rule.check_dependency(dep) is None
        assert self.rule.check_dependency(dep_unpinned_repr) is None
