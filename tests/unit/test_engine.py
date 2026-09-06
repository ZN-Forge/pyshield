"""Unit tests for ScanEngine and file discovery."""

from pathlib import Path

import pytest

from pyshield.config.models import ScanConfig
from pyshield.core.engine import ScanEngine, discover_python_files, should_exclude
from pyshield.core.models import Severity


class TestDiscovery:
    def test_should_exclude_matching_directory(self) -> None:
        patterns = [".git", ".venv", "__pycache__", "node_modules"]
        assert should_exclude(Path(".venv/lib/site-packages/pkg.py"), patterns) is True
        assert should_exclude(Path("src/__pycache__/app.cpython-311.pyc"), patterns) is True
        assert should_exclude(Path(".git/hooks/pre-commit.py"), patterns) is True
        assert should_exclude(Path("node_modules/my-pkg/index.py"), patterns) is True
        assert should_exclude(Path("src/app/main.py"), patterns) is False

    def test_discover_python_files_in_tree(self, tmp_path: Path) -> None:
        # Create directory tree
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.py").write_text("print('hello')", encoding="utf-8")
        (tmp_path / "src" / "utils.py").write_text("print('utils')", encoding="utf-8")
        (tmp_path / "src" / "notes.txt").write_text("not python", encoding="utf-8")

        # Excluded directory
        (tmp_path / ".venv").mkdir()
        (tmp_path / ".venv" / "bad.py").write_text("print('ignored')", encoding="utf-8")

        found = discover_python_files(tmp_path, [".venv"])
        found_names = [f.name for f in found]
        assert "main.py" in found_names
        assert "utils.py" in found_names
        assert "bad.py" not in found_names
        assert "notes.txt" not in found_names

    def test_discover_single_file(self, tmp_path: Path) -> None:
        f = tmp_path / "single.py"
        f.write_text("x = 1", encoding="utf-8")
        found = discover_python_files(f, [])
        assert found == [f]

    def test_discover_nonexistent_path_raises(self, tmp_path: Path) -> None:
        missing = tmp_path / "ghost_path"
        with pytest.raises(FileNotFoundError):
            discover_python_files(missing, [])


class TestScanEngine:
    def test_run_scan_with_findings(self, tmp_path: Path) -> None:
        vuln_file = tmp_path / "vuln.py"
        vuln_file.write_text("import os\nos.system('echo hi')", encoding="utf-8")

        config = ScanConfig(target_paths=[tmp_path])
        engine = ScanEngine(config=config)
        result = engine.run()

        assert result.summary.files_scanned == 1
        assert result.summary.files_failed == 0
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == "PS103"
        assert result.summary.findings_count[Severity.HIGH] == 1

    def test_run_scan_with_clean_files(self, tmp_path: Path) -> None:
        clean_file = tmp_path / "clean.py"
        clean_file.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

        config = ScanConfig(target_paths=[tmp_path])
        engine = ScanEngine(config=config)
        result = engine.run()

        assert result.summary.files_scanned == 1
        assert len(result.findings) == 0
        assert result.summary.total_findings == 0

    def test_run_scan_with_syntax_error(self, tmp_path: Path) -> None:
        broken_file = tmp_path / "broken.py"
        broken_file.write_text("def broken(\n", encoding="utf-8")

        config = ScanConfig(target_paths=[tmp_path])
        engine = ScanEngine(config=config)
        result = engine.run()

        assert result.summary.files_scanned == 0
        assert result.summary.files_failed == 1
        assert len(result.diagnostics) == 1
        assert result.diagnostics[0].error_type == "SyntaxError"
