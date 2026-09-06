"""Unit tests for ASTAnalyzer."""

from pathlib import Path

from pyshield.core.analyzer import ASTAnalyzer
from pyshield.rules.builtin.dangerous_eval import DangerousEvalRule


class TestASTAnalyzer:
    def test_valid_source_analysis(self) -> None:
        analyzer = ASTAnalyzer(rules=[DangerousEvalRule()])
        src = "eval('1+1')"
        findings, diag = analyzer.analyze_source(src, Path("test.py"))
        assert diag is None
        assert len(findings) == 1
        assert findings[0].rule_id == "PS101"

    def test_syntax_error_handled_gracefully(self) -> None:
        analyzer = ASTAnalyzer(rules=[DangerousEvalRule()])
        broken_src = "def broken(\n  this is invalid syntax !!!"
        findings, diag = analyzer.analyze_source(broken_src, Path("broken.py"))
        assert len(findings) == 0
        assert diag is not None
        assert diag.error_type == "SyntaxError"
        assert diag.file_path == Path("broken.py")
        assert diag.line is not None

    def test_file_size_limit_exceeded(self, tmp_path: Path) -> None:
        analyzer = ASTAnalyzer(rules=[DangerousEvalRule()])
        large_file = tmp_path / "large.py"
        large_file.write_text("x = 1\n" * 100, encoding="utf-8")

        # Set max limit smaller than file size
        findings, diag = analyzer.analyze_file(large_file, max_file_size_bytes=10)
        assert len(findings) == 0
        assert diag is not None
        assert diag.error_type == "FileSizeLimitExceeded"

    def test_nonexistent_file_read_error(self, tmp_path: Path) -> None:
        analyzer = ASTAnalyzer(rules=[DangerousEvalRule()])
        missing = tmp_path / "does_not_exist.py"
        findings, diag = analyzer.analyze_file(missing)
        assert len(findings) == 0
        assert diag is not None
        assert diag.error_type == "ReadError"

    def test_unicode_replacement_reading(self, tmp_path: Path) -> None:
        analyzer = ASTAnalyzer(rules=[DangerousEvalRule()])
        non_utf8_file = tmp_path / "latin.py"
        # Write bytes that are not valid UTF-8
        non_utf8_file.write_bytes(b"# \xff\xfe non-utf8 comment\neval('1')\n")

        findings, diag = analyzer.analyze_file(non_utf8_file)
        assert diag is None
        assert len(findings) == 1
