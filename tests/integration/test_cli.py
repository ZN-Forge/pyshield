"""Integration tests for PyShield CLI."""

from typer.testing import CliRunner

from pyshield import __version__
from pyshield.cli.main import app

runner = CliRunner()


class TestCLI:
    def test_version_flag(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert f"PyShield {__version__}" in result.output

    def test_scan_benign_directory_exit_0(self) -> None:
        result = runner.invoke(app, ["scan", "tests/fixtures/benign"])
        assert result.exit_code == 0
        assert "No security findings detected" in result.output
        assert "Total findings: 0" in result.output

    def test_scan_vulnerable_directory_exit_1(self) -> None:
        result = runner.invoke(app, ["scan", "tests/fixtures/vulnerable"])
        assert result.exit_code == 1
        assert "PS101" in result.output
        assert "PS102" in result.output
        assert "PS103" in result.output
        assert "PS104" in result.output

    def test_scan_with_rules_disabled(self) -> None:
        result = runner.invoke(
            app,
            [
                "scan",
                "tests/fixtures/vulnerable",
                "--disable-rule",
                "PS101",
                "--disable-rule",
                "PS102",
                "--disable-rule",
                "PS103",
                "--disable-rule",
                "PS104",
            ],
        )
        assert result.exit_code == 0
        assert "Total findings: 0" in result.output

    def test_scan_with_single_rule_enabled(self) -> None:
        result = runner.invoke(
            app,
            [
                "scan",
                "tests/fixtures/vulnerable",
                "--enable-rule",
                "PS101",
            ],
        )
        assert result.exit_code == 1
        assert "PS101" in result.output
        assert "PS102" not in result.output
        assert "PS103" not in result.output
        assert "PS104" not in result.output

    def test_scan_fail_on_threshold(self) -> None:
        # Run only PS103 (HIGH), but set threshold to CRITICAL -> exit code 0
        result = runner.invoke(
            app,
            [
                "scan",
                "tests/fixtures/vulnerable",
                "--enable-rule",
                "PS103",
                "--fail-on",
                "CRITICAL",
            ],
        )
        assert result.exit_code == 0
        assert "PS103" in result.output  # finding displayed, but didn't fail build

    def test_scan_nonexistent_path_exit_2(self) -> None:
        result = runner.invoke(app, ["scan", "nonexistent_dir_random_12345"])
        assert result.exit_code == 2

    def test_scan_syntax_error_fixture_exit_2(self) -> None:
        result = runner.invoke(app, ["scan", "tests/fixtures/syntax_error"])
        assert result.exit_code == 2
        assert "SyntaxError" in result.output
