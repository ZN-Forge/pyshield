"""Tests for PS103: os.system() rule."""

from tests.conftest import make_context

from pyshield.core.models import Confidence, Severity
from pyshield.rules.builtin.os_system import OsSystemRule


class TestOsSystemRule:
    def setup_method(self) -> None:
        self.rule = OsSystemRule()

    # --- Positive cases ---
    def test_direct_os_system(self) -> None:
        src = "import os\nos.system('echo hello')"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "PS103"
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH
        assert f.cwe == "CWE-78"
        assert f.line == 2

    def test_os_system_aliased_module(self) -> None:
        src = "import os as operating_system\noperating_system.system('ls -la')"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert findings[0].line == 2

    def test_from_os_import_system(self) -> None:
        src = "from os import system\nsystem('whoami')"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert findings[0].line == 2

    def test_from_os_import_system_aliased(self) -> None:
        src = "from os import system as sys_exec\nsys_exec('id')"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert findings[0].line == 2

    # --- Negative cases ---
    def test_platform_system_safe(self) -> None:
        src = "import platform\nos_name = platform.system()\n"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_unrelated_custom_system_function(self) -> None:
        src = "def system(name):\n    return f'System: {name}'\nres = system('linux')\n"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_method_named_system_on_custom_class(self) -> None:
        src = (
            "class AudioDevice:\n"
            "    def system(self):\n"
            "        pass\n"
            "dev = AudioDevice()\n"
            "dev.system()\n"
        )
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_variable_named_system(self) -> None:
        src = "system = 'Solar'\nprint(system)\n"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    # --- Edge cases ---
    def test_multiple_os_system_calls(self) -> None:
        src = "import os\nos.system('cmd1')\nos.system('cmd2')\n"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 2
        assert findings[0].line == 2
        assert findings[1].line == 3
