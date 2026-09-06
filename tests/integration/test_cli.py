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

        # Verify all Phase 1 and Phase 2 rules are triggered
        expected_rules = [
            "PS101",
            "PS102",
            "PS103",
            "PS104",
            "PS201",
            "PS202",
            "PS203",
            "PS301",
            "PS302",
            "PS303",
        ]
        for rule_id in expected_rules:
            assert rule_id in result.output

        # Verify secret leakage prevention: no raw sensitive values in output
        assert "fake_hardcoded_password_12345!" not in result.output
        assert "fakekeydata" not in result.output
        assert "AKIA9988776655443322" not in result.output
        assert "AKIA****************" in result.output

    def test_scan_with_all_rules_disabled(self) -> None:
        disabled_args = []
        for rule_id in [
            "PS101",
            "PS102",
            "PS103",
            "PS104",
            "PS201",
            "PS202",
            "PS203",
            "PS301",
            "PS302",
            "PS303",
        ]:
            disabled_args.extend(["--disable-rule", rule_id])

        result = runner.invoke(app, ["scan", "tests/fixtures/vulnerable", *disabled_args])
        assert result.exit_code == 0
        assert "Total findings: 0" in result.output

    def test_scan_with_single_rule_enabled(self) -> None:
        result = runner.invoke(
            app,
            [
                "scan",
                "tests/fixtures/vulnerable",
                "--enable-rule",
                "PS201",
            ],
        )
        assert result.exit_code == 1
        assert "PS201" in result.output
        assert "PS101" not in result.output
        assert "PS301" not in result.output

    def test_scan_fail_on_threshold(self) -> None:
        # Run only PS301 (MEDIUM), but set threshold to HIGH -> exit code 0
        result = runner.invoke(
            app,
            [
                "scan",
                "tests/fixtures/vulnerable",
                "--enable-rule",
                "PS301",
                "--fail-on",
                "HIGH",
            ],
        )
        assert result.exit_code == 0
        assert "PS301" in result.output

    def test_scan_nonexistent_path_exit_2(self) -> None:
        result = runner.invoke(app, ["scan", "nonexistent_dir_random_12345"])
        assert result.exit_code == 2

    def test_scan_syntax_error_fixture_exit_2(self) -> None:
        result = runner.invoke(app, ["scan", "tests/fixtures/syntax_error"])
        assert result.exit_code == 2
        assert "SyntaxError" in result.output
