"""Terminal reporter presenting scan results cleanly using Rich."""

import io

from rich.console import Console

from pyshield.core.models import ScanResult, Severity

SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold dark_orange",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


class TerminalReporter:
    """Renders formatted scan findings and summary metrics to the terminal."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def render(self, result: ScanResult) -> None:
        """Output the complete scan report to the console."""
        self.console.print("[bold cyan]PyShield Security Scan[/bold cyan]")
        self.console.print("------------------------------------")
        self.console.print(f"Files scanned: {result.summary.files_scanned}")
        if result.summary.files_failed > 0:
            self.console.print(
                f"[yellow]Files with diagnostics: {result.summary.files_failed}[/yellow]"
            )
        self.console.print()

        # Render file diagnostics if any
        if result.diagnostics:
            self.console.print("[bold yellow]Diagnostics:[/bold yellow]")
            for diag in result.diagnostics:
                loc = f"{diag.file_path.as_posix()}"
                if diag.line is not None:
                    loc += f":{diag.line}"
                    if diag.column is not None:
                        loc += f":{diag.column}"
                self.console.print(f"  [yellow]![/yellow] [{diag.error_type}] {loc}")
                self.console.print(f"    {diag.message}")
            self.console.print()

        # Render findings
        if result.findings:
            for finding in result.findings:
                style = SEVERITY_STYLES.get(finding.severity, "white")
                sev_label = finding.severity.value.ljust(8)
                header = (
                    f"[{style}]{sev_label}[/{style}]  "
                    f"[bold]{finding.rule_id}[/bold]  {finding.title}"
                )
                self.console.print(header)
                loc = f"{finding.file_path.as_posix()}:{finding.line}:{finding.column}"
                self.console.print(f"          [dim]{loc}[/dim]")
                if finding.snippet:
                    self.console.print(f"          [dim italic]> {finding.snippet}[/dim italic]")
                self.console.print()
        else:
            self.console.print("[green]No security findings detected.[/green]\n")

        # Render summary
        self.console.print("Summary")
        self.console.print("------------------------------------")
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = result.summary.findings_count.get(sev, 0)
            style = SEVERITY_STYLES.get(sev, "white")
            label = f"{sev.value.capitalize()}:".ljust(10)
            self.console.print(f"[{style}]{label}[/{style}] {count}")

        self.console.print(f"\nTotal findings: {result.summary.total_findings}")
        self.console.print(f"Scan duration:  {result.summary.duration_seconds}s\n")

    def render_to_string(self, result: ScanResult) -> str:
        """Render the report to a string (useful for testing and capturing output)."""
        buf = io.StringIO()
        capture_console = Console(file=buf, force_terminal=False, color_system=None)
        reporter = TerminalReporter(console=capture_console)
        reporter.render(result)
        return buf.getvalue()
