"""Base abstractions and AST context for PyShield security rules."""

import ast
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from pyshield.core.models import Confidence, Finding, Severity


@dataclass(frozen=True)
class ASTContext:
    """Encapsulates file source code, AST, and semantic helpers for analysis."""

    file_path: Path
    source_code: str
    tree: ast.AST
    lines: list[str] = field(default_factory=list)
    imports: dict[str, str] = field(default_factory=dict)

    @classmethod
    def create(cls, file_path: Path, source_code: str, tree: ast.AST) -> "ASTContext":
        """Factory method to parse lines and analyze imports."""
        lines = source_code.splitlines()
        imports = cls._collect_imports(tree)
        return cls(
            file_path=file_path,
            source_code=source_code,
            tree=tree,
            lines=lines,
            imports=imports,
        )

    @staticmethod
    def _collect_imports(tree: ast.AST) -> dict[str, str]:
        """Collect top-level and inner imports mapping local alias to qualified target."""
        resolved: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    resolved[local_name] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    qualified = f"{module}.{alias.name}" if module else alias.name
                    resolved[local_name] = qualified
        return resolved

    def get_snippet(self, line: int) -> str | None:
        """Return the source code line (1-indexed) safely."""
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1].strip()
        return None

    def resolve_name(self, name: str) -> str:
        """Resolve a local identifier through known imports."""
        return self.imports.get(name, name)


class BaseRule(ABC):
    """Abstract base class for all PyShield static security rules."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    cwe: str
    remediation: str

    def create_finding(
        self,
        context: ASTContext,
        node: ast.AST,
        message: str,
        end_node: ast.AST | None = None,
        custom_severity: Severity | None = None,
        custom_confidence: Confidence | None = None,
    ) -> Finding:
        """Convenience method to construct a validated Finding from an AST node."""
        line = getattr(node, "lineno", 1)
        # ast col_offset is 0-indexed; present as 1-indexed column for user consistency
        col = getattr(node, "col_offset", 0) + 1

        end_line: int | None = getattr(end_node or node, "end_lineno", None)
        end_col: int | None = None
        raw_end_col = getattr(end_node or node, "end_col_offset", None)
        if raw_end_col is not None:
            end_col = raw_end_col + 1

        snippet = context.get_snippet(line)

        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=custom_severity or self.severity,
            confidence=custom_confidence or self.confidence,
            file_path=context.file_path,
            line=line,
            column=col,
            end_line=end_line,
            end_column=end_col,
            message=message,
            description=self.description,
            remediation=self.remediation,
            cwe=self.cwe,
            snippet=snippet,
        )

    @abstractmethod
    def check(self, context: ASTContext) -> list[Finding]:
        """Execute the rule against the parsed ASTContext and return findings."""
        raise NotImplementedError
