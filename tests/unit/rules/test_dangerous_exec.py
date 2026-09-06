"""Tests for PS102: Dangerous exec() rule."""

from tests.conftest import make_context

from pyshield.core.models import Confidence, Severity
from pyshield.rules.builtin.dangerous_exec import DangerousExecRule


class TestDangerousExecRule:
    def setup_method(self) -> None:
        self.rule = DangerousExecRule()

    # --- Positive cases ---
    def test_direct_exec_literal(self) -> None:
        src = "exec(\"import os; os.system('ls')\")"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "PS102"
        assert f.severity == Severity.CRITICAL
        assert f.confidence == Confidence.HIGH
        assert f.cwe == "CWE-95"
        assert f.line == 1

    def test_exec_with_globals_locals(self) -> None:
        src = 'code = "x = 10"\nexec(code, {"x": 0}, {})'
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert findings[0].line == 2

    def test_exec_inside_class_method(self) -> None:
        src = "class Runner:\n    def run(self, code):\n        exec(code)\n"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert findings[0].line == 3

    # --- Negative cases ---
    def test_qt_app_exec(self) -> None:
        src = "app = QApplication([])\nsys.exit(app.exec())\n"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_runner_exec_method(self) -> None:
        src = "runner = TaskRunner()\nrunner.exec()\n"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_sqlmodel_session_exec(self) -> None:
        src = "session.exec(select(User))\n"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_exec_function_def(self) -> None:
        src = "def exec(cmd):\n    return cmd\n"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_exec_attribute_assignment(self) -> None:
        src = "config.exec = True\n"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    # --- Edge cases ---
    def test_multiple_exec_calls(self) -> None:
        src = "exec('a = 1')\nx = 2\nexec('b = 3')\n"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 2
        assert findings[0].line == 1
        assert findings[1].line == 3
