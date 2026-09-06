"""Unit tests for dependency parsers."""

from pathlib import Path

from pyshield.dependencies.models import Dependency, DependencySourceType
from pyshield.dependencies.parser import (
    deduplicate_dependencies_for_vulnerability_scan,
    normalize_package_name,
    parse_dependency_file,
    parse_pyproject_toml,
    parse_requirements_txt,
    parse_uv_lock,
)


class TestDependencyParsers:
    def test_normalize_package_name(self) -> None:
        assert normalize_package_name("Flask-Login") == "flask-login"
        assert normalize_package_name("typing_extensions") == "typing-extensions"
        assert normalize_package_name("pkg.name") == "pkg-name"
        assert normalize_package_name("Requests") == "requests"

    def test_parse_requirements_txt(self, tmp_path: Path) -> None:
        req_content = (
            "# Top comment\n"
            "\n"
            "requests==2.31.0\n"
            "Django>=4.2 # Web framework\n"
            "flask\n"
            "urllib3<2.0,>=1.26.5\n"
            "pytest[dev]>=8.0.0; python_version >= '3.11'\n"
            "-r other-requirements.txt\n"
            "--extra-index-url https://example.com/pypi\n"
        )
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(req_content, encoding="utf-8")

        deps = parse_requirements_txt(req_file)
        assert len(deps) == 5

        # requests
        assert deps[0].name == "requests"
        assert deps[0].raw_name == "requests"
        assert deps[0].version == "2.31.0"
        assert deps[0].specifier == "==2.31.0"
        assert deps[0].line == 3

        # django
        assert deps[1].name == "django"
        assert deps[1].version is None
        assert deps[1].specifier == ">=4.2"
        assert deps[1].line == 4

        # flask (unpinned)
        assert deps[2].name == "flask"
        assert deps[2].version is None
        assert deps[2].specifier is None
        assert deps[2].line == 5

        # urllib3
        assert deps[3].name == "urllib3"
        assert deps[3].specifier == "<2.0,>=1.26.5"

        # pytest
        assert deps[4].name == "pytest"
        assert deps[4].specifier == ">=8.0.0"

    def test_parse_pyproject_toml(self, tmp_path: Path) -> None:
        toml_content = """
[project]
name = "demo-app"
version = "0.1.0"
dependencies = [
    "requests==2.31.0",
    "flask",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
]

[dependency-groups]
docs = [
    "mkdocs>=1.5.0",
]
"""
        pyproject_file = tmp_path / "pyproject.toml"
        pyproject_file.write_text(toml_content, encoding="utf-8")

        deps = parse_pyproject_toml(pyproject_file)
        names = {d.name for d in deps}
        assert names == {"requests", "flask", "pytest", "mkdocs"}

        req_dep = next(d for d in deps if d.name == "requests")
        assert req_dep.version == "2.31.0"

        flask_dep = next(d for d in deps if d.name == "flask")
        assert flask_dep.specifier is None

    def test_parse_uv_lock(self, tmp_path: Path) -> None:
        lock_content = """
version = 1
revision = 1

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "urllib3"
version = "2.0.7"
source = { registry = "https://pypi.org/simple" }
"""
        lock_file = tmp_path / "uv.lock"
        lock_file.write_text(lock_content, encoding="utf-8")

        deps = parse_uv_lock(lock_file)
        assert len(deps) == 2
        assert deps[0].name == "requests"
        assert deps[0].version == "2.31.0"
        assert deps[0].source_type == DependencySourceType.UV_LOCK

        assert deps[1].name == "urllib3"
        assert deps[1].version == "2.0.7"

    def test_parse_dependency_file_dispatcher(self, tmp_path: Path) -> None:
        req_file = tmp_path / "requirements-dev.txt"
        req_file.write_text("pytest>=8.0.0\n", encoding="utf-8")

        deps = parse_dependency_file(req_file)
        assert len(deps) == 1
        assert deps[0].name == "pytest"

    def test_deduplicate_dependencies_prefers_uv_lock(self, tmp_path: Path) -> None:
        dep_req = Dependency(
            name="requests",
            raw_name="requests",
            version=None,
            specifier=None,
            source_file=tmp_path / "requirements.txt",
            source_type=DependencySourceType.REQUIREMENTS_TXT,
        )
        dep_pyproject = Dependency(
            name="requests",
            raw_name="requests",
            version=None,
            specifier=">=2.30",
            source_file=tmp_path / "pyproject.toml",
            source_type=DependencySourceType.PYPROJECT_TOML,
        )
        dep_lock = Dependency(
            name="requests",
            raw_name="requests",
            version="2.31.0",
            specifier="==2.31.0",
            source_file=tmp_path / "uv.lock",
            source_type=DependencySourceType.UV_LOCK,
        )

        deduped = deduplicate_dependencies_for_vulnerability_scan(
            [dep_req, dep_pyproject, dep_lock]
        )
        assert len(deduped) == 1
        assert deduped[0].source_type == DependencySourceType.UV_LOCK
        assert deduped[0].version == "2.31.0"
