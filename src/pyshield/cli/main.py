"""Command-line interface for PyShield."""

import sys
from pathlib import Path

import typer

from pyshield import __version__
from pyshield.config.models import DEFAULT_EXCLUDES, ScanConfig
from pyshield.core.engine import ScanEngine
from pyshield.core.models import Severity
from pyshield.reporters.terminal import TerminalReporter

app = typer.Typer(
    name="pyshield",
    help="PyShield: Developer-focused open-source Python security analysis platform.",
    no_args_is_help=True,
    add_completion=False,
)


def version_callback(value: bool) -> None:
    """Print the PyShield version and exit."""
    if value:
        typer.echo(f"PyShield {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-v",
        help="Show PyShield version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """PyShield root command."""


@app.command(name="scan", help="Scan Python files or directories for security vulnerabilities.")
def scan(
    paths: list[Path] = typer.Argument(
        None,
        help="One or more file or directory paths to scan (default: current directory).",
    ),
    fail_on: Severity = typer.Option(
        Severity.LOW,
        "--fail-on",
        help="Minimum severity threshold to trigger exit code 1 (LOW, MEDIUM, HIGH, CRITICAL).",
        case_sensitive=False,
    ),
    exclude: list[str] = typer.Option(
        None,
        "--exclude",
        "-e",
        help="Additional glob patterns or directory names to exclude.",
    ),
    disable_rule: list[str] = typer.Option(
        None,
        "--disable-rule",
        "-d",
        help="Rule IDs to disable (e.g. PS101).",
    ),
    enable_rule: list[str] = typer.Option(
        None,
        "--enable-rule",
        help="Explicit rule IDs to enable (only these will run).",
    ),
) -> None:
    """Run deterministic static security analysis on the specified paths."""
    target_paths = paths if paths else [Path(".")]

    # Validate that all target paths exist; exit with code 2 if not
    for path in target_paths:
        if not path.exists():
            sys.stderr.write(f"Error: Target path does not exist: {path}\n")
            raise typer.Exit(code=2)

    # Build scan configuration
    exclude_patterns = list(DEFAULT_EXCLUDES)
    if exclude:
        exclude_patterns.extend(exclude)

    config = ScanConfig(
        target_paths=target_paths,
        exclude_patterns=exclude_patterns,
        fail_on=fail_on,
        disabled_rules=set(disable_rule) if disable_rule else set(),
        enabled_rules=set(enable_rule) if enable_rule else None,
    )

    try:
        engine = ScanEngine(config=config)
        result = engine.run()
    except Exception as err:
        sys.stderr.write(f"Error during scan execution: {err}\n")
        raise typer.Exit(code=2) from err

    reporter = TerminalReporter()
    reporter.render(result)

    # Exit code determination
    # 0 = No findings at or above configured failure threshold
    # 1 = One or more findings at or above configured threshold
    # 2 = Scan error (e.g. zero files could be parsed and all failed)
    if result.summary.files_scanned == 0 and result.summary.files_failed > 0:
        raise typer.Exit(code=2)

    if any(finding.severity >= fail_on for finding in result.findings):
        raise typer.Exit(code=1)

    raise typer.Exit(code=0)
