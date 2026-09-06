"""Integration tests for discovery and scan orchestration across complex folder trees."""

from pathlib import Path

from pyshield.config.models import ScanConfig
from pyshield.core.engine import ScanEngine, discover_python_files


class TestDiscoveryIntegration:
    def test_nested_traversal_and_custom_exclusions(self, tmp_path: Path) -> None:
        # Build nested directory tree:
        # tmp_path/
        #   app/
        #     api/
        #       routes.py
        #     services/
        #       auth.py
        #   tests/
        #     test_routes.py
        #   node_modules/
        #     package/
        #       bad.py
        #   legacy/
        #     old.py

        (tmp_path / "app" / "api").mkdir(parents=True)
        (tmp_path / "app" / "services").mkdir(parents=True)
        (tmp_path / "tests").mkdir(parents=True)
        (tmp_path / "node_modules" / "package").mkdir(parents=True)
        (tmp_path / "legacy").mkdir(parents=True)

        (tmp_path / "app" / "api" / "routes.py").write_text("x = 1", encoding="utf-8")
        (tmp_path / "app" / "services" / "auth.py").write_text("y = 2", encoding="utf-8")
        (tmp_path / "tests" / "test_routes.py").write_text("assert True", encoding="utf-8")
        (tmp_path / "node_modules" / "package" / "bad.py").write_text("z = 3", encoding="utf-8")
        (tmp_path / "legacy" / "old.py").write_text("w = 4", encoding="utf-8")

        discovered = discover_python_files(tmp_path, exclude_patterns=["node_modules", "legacy"])
        discovered_rel = [f.relative_to(tmp_path).as_posix() for f in discovered]

        assert "app/api/routes.py" in discovered_rel
        assert "app/services/auth.py" in discovered_rel
        assert "tests/test_routes.py" in discovered_rel
        assert "node_modules/package/bad.py" not in discovered_rel
        assert "legacy/old.py" not in discovered_rel

    def test_multi_target_scan(self, tmp_path: Path) -> None:
        dir1 = tmp_path / "target1"
        dir2 = tmp_path / "target2"
        dir1.mkdir()
        dir2.mkdir()

        (dir1 / "code1.py").write_text("import os; os.system('echo 1')", encoding="utf-8")
        (dir2 / "code2.py").write_text("eval('2')", encoding="utf-8")

        config = ScanConfig(target_paths=[dir1, dir2])
        engine = ScanEngine(config=config)
        result = engine.run()

        assert result.summary.files_scanned == 2
        assert len(result.findings) == 2
        rule_ids = {f.rule_id for f in result.findings}
        assert rule_ids == {"PS101", "PS103"}
