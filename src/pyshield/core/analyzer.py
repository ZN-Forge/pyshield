"""AST Analyzer: safely reads, parses, and executes rules on Python files."""

import ast
from pathlib import Path

from pyshield.core.models import FileDiagnostic, Finding
from pyshield.rules.base import ASTContext, BaseRule


class ASTAnalyzer:
    """Performs static analysis on Python source files using standard ast."""

    def __init__(self, rules: list[BaseRule]) -> None:
        self.rules = rules

    def analyze_source(
        self,
        source_code: str,
        file_path: Path,
    ) -> tuple[list[Finding], FileDiagnostic | None]:
        """Analyze a string of Python source code against configured rules."""
        try:
            tree = ast.parse(source_code, filename=str(file_path))
        except SyntaxError as err:
            diagnostic = FileDiagnostic(
                file_path=file_path,
                error_type="SyntaxError",
                message=err.msg or "Syntax error during parsing",
                line=err.lineno,
                column=err.offset,
            )
            return [], diagnostic
        except Exception as err:
            diagnostic = FileDiagnostic(
                file_path=file_path,
                error_type=type(err).__name__,
                message=str(err) or "Failed to parse AST",
            )
            return [], diagnostic

        context = ASTContext.create(file_path=file_path, source_code=source_code, tree=tree)
        findings: list[Finding] = []

        for rule in self.rules:
            rule_findings = rule.check(context)
            findings.extend(rule_findings)

        return findings, None

    def analyze_file(
        self,
        file_path: Path,
        max_file_size_bytes: int = 10 * 1024 * 1024,
    ) -> tuple[list[Finding], FileDiagnostic | None]:
        """Read and analyze a single Python file from disk."""
        try:
            stat = file_path.stat()
            if stat.st_size > max_file_size_bytes:
                return [], FileDiagnostic(
                    file_path=file_path,
                    error_type="FileSizeLimitExceeded",
                    message=(
                        f"File size ({stat.st_size} bytes) exceeds "
                        f"limit ({max_file_size_bytes} bytes)"
                    ),
                )

            # Read with utf-8 and replacement characters for invalid encodings
            source_code = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as err:
            return [], FileDiagnostic(
                file_path=file_path,
                error_type="ReadError",
                message=f"Could not read file: {err}",
            )

        return self.analyze_source(source_code=source_code, file_path=file_path)
