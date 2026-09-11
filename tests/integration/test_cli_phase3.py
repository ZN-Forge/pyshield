"""Integration tests for Phase 3: Configuration & Dependency Security CLI."""

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from pyshield import __version__
from pyshield.cli.main import app

runner = CliRunner()


class TestCLIPhase3:
    def test_version_output_0_3_0(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert f"PyShield {__version__}" in result.output
        assert "0.3.0" in result.output

    def test_scan_unpinned_requirements_triggers_ps802(self, tmp_path: Path) -> None:
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("flask\n", encoding="utf-8")

        result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "MEDIUM"])
        assert result.exit_code == 1
        assert "PS802" in result.output
        assert "Unpinned dependency" in result.output

    def test_scan_pinned_requirements_clean(self, tmp_path: Path) -> None:
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("flask==3.0.0\n", encoding="utf-8")

        # Mock OSV query to return clean
        with patch("pyshield.dependencies.providers.osv.OSVProvider.query_batch") as mock_batch:
            mock_batch.return_value = {}
            result = runner.invoke(app, ["scan", str(tmp_path)])
            assert result.exit_code == 0
            assert "Total findings: 0" in result.output

    def test_scan_offline_flag(self, tmp_path: Path) -> None:
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.20.0\n", encoding="utf-8")

        with patch("pyshield.dependencies.providers.osv.OSVProvider.query_batch") as mock_batch:
            result = runner.invoke(app, ["scan", str(tmp_path), "--offline"])
            # In offline mode, OSV query_batch should not be called
            assert mock_batch.call_count == 0
            assert result.exit_code == 0
            assert (
                "OfflineMode" in result.output or "No security findings detected" in result.output
            )

    def test_scan_debug_mode_config_triggers_ps701(self, tmp_path: Path) -> None:
        py_file = tmp_path / "settings.py"
        py_file.write_text("DEBUG = True\n", encoding="utf-8")

        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 1
        assert "PS701" in result.output
        assert "Debug mode enabled" in result.output

    def test_scan_insecure_tls_triggers_ps702(self, tmp_path: Path) -> None:
        py_file = tmp_path / "fetch.py"
        py_file.write_text(
            'import requests\nrequests.get("https://example.com", verify=False)\n', encoding="utf-8"
        )

        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 1
        assert "PS702" in result.output
        assert "TLS certificate verification disabled" in result.output
