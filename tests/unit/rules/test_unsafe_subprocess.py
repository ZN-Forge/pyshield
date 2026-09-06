"""Tests for PS104: Unsafe subprocess rule."""

from tests.conftest import make_context

from pyshield.core.models import Confidence, Severity
from pyshield.rules.builtin.unsafe_subprocess import UnsafeSubprocessRule


class TestUnsafeSubprocessRule:
    def setup_method(self) -> None:
        self.rule = UnsafeSubprocessRule()

    # --- Positive cases ---
    def test_subprocess_run_shell_true(self) -> None:
        src = "import subprocess\nsubprocess.run('rm -rf /', shell=True)"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "PS104"
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH
        assert f.cwe == "CWE-78"
        assert f.line == 2

    def test_subprocess_popen_shell_true(self) -> None:
        src = "import subprocess\np = subprocess.Popen('cat ' + file, shell=True)"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert findings[0].line == 2

    def test_subprocess_call_shell_true(self) -> None:
        src = "import subprocess\nsubprocess.call('ls', shell=True)"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1

    def test_subprocess_check_call_shell_true(self) -> None:
        src = "import subprocess\nsubprocess.check_call('make', shell=True)"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1

    def test_subprocess_check_output_shell_true(self) -> None:
        src = "import subprocess\nout = subprocess.check_output('whoami', shell=True)"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1

    def test_subprocess_shell_literal_one(self) -> None:
        src = "import subprocess\nsubprocess.run('cmd', shell=1)"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1

    def test_subprocess_aliased_import(self) -> None:
        src = "import subprocess as sp\nsp.run('cmd', shell=True)"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1

    def test_from_subprocess_import_run(self) -> None:
        src = "from subprocess import run\nrun('cmd', shell=True)"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1

    def test_from_subprocess_import_popen_aliased(self) -> None:
        src = "from subprocess import Popen as SubProcess\nSubProcess('cmd', shell=True)"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1

    # --- Negative cases ---
    def test_subprocess_run_default_safe(self) -> None:
        src = "import subprocess\nsubprocess.run(['ls', '-la'], check=True)"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_subprocess_run_explicit_shell_false(self) -> None:
        src = "import subprocess\nsubprocess.run(['git', 'status'], shell=False)"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_subprocess_shell_zero(self) -> None:
        src = "import subprocess\nsubprocess.run(['echo', 'hi'], shell=0)"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_subprocess_shell_none(self) -> None:
        src = "import subprocess\nsubprocess.run(['echo', 'hi'], shell=None)"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_unrelated_object_run_with_shell_kwarg(self) -> None:
        src = (
            "class CustomRunner:\n"
            "    def run(self, cmd, shell=False):\n"
            "        pass\n"
            "r = CustomRunner()\n"
            "r.run('cmd', shell=True)\n"
        )
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_arbitrary_variable_shell_not_flagged(self) -> None:
        # Phase 1 conservative rule: do not flag dynamic variable config.shell
        src = "import subprocess\nsubprocess.run('cmd', shell=config.shell)"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    # --- Edge cases ---
    def test_subprocess_multiple_kwargs_ordering(self) -> None:
        src = (
            "import subprocess\n"
            "subprocess.run("
            "args='echo 1', timeout=10, capture_output=True, shell=True, check=False"
            ")"
        )
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
