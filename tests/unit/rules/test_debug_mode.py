"""Unit tests for PS701: DebugModeRule."""

from pathlib import Path

from pyshield.core.analyzer import ASTAnalyzer
from pyshield.core.models import Severity
from pyshield.rules.builtin.debug_mode import DebugModeRule


class TestDebugModeRule:
    def setup_method(self) -> None:
        self.rule = DebugModeRule()
        self.analyzer = ASTAnalyzer(rules=[self.rule])
        self.dummy_path = Path("test_settings.py")

    def test_debug_true_detected(self) -> None:
        code = "DEBUG = True\n"
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 1
        assert findings[0].rule_id == "PS701"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].cwe == "CWE-489"
        assert findings[0].line == 1

    def test_annotated_debug_true_detected(self) -> None:
        code = "DEBUG: bool = True\n"
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 1
        assert findings[0].rule_id == "PS701"

    def test_debug_integer_one_detected(self) -> None:
        code = "DEBUG = 1\n"
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 1

    def test_debug_false_safe(self) -> None:
        code = "DEBUG = False\n"
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 0

    def test_debug_zero_safe(self) -> None:
        code = "DEBUG = 0\n"
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 0

    def test_debug_from_env_safe(self) -> None:
        code = "import os\nDEBUG = os.environ.get('DEBUG', 'False') == 'True'\n"
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 0

    def test_unrelated_debug_vars_ignored(self) -> None:
        code = "MY_DEBUG = True\nDEBUG_TOOLBAR = True\nDEBUG_LOGGING = True\nDEBUG_MODE = True\n"
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 0
