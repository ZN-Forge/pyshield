"""Tests for PS101: Dangerous eval() rule."""

from tests.conftest import make_context

from pyshield.core.models import Confidence, Severity
from pyshield.rules.builtin.dangerous_eval import DangerousEvalRule


class TestDangerousEvalRule:
    def setup_method(self) -> None:
        self.rule = DangerousEvalRule()

    # --- Positive cases ---
    def test_direct_eval_literal(self) -> None:
        src = 'res = eval("1 + 1")'
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "PS101"
        assert f.severity == Severity.CRITICAL
        assert f.confidence == Confidence.HIGH
        assert f.cwe == "CWE-95"
        assert f.line == 1

    def test_direct_eval_variable(self) -> None:
        src = 'user_input = \'__import__("os").system("ls")\'\neval(user_input)'
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert findings[0].line == 2

    def test_eval_inside_function(self) -> None:
        src = "def process(payload):\n    return eval(payload)\n"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert findings[0].line == 2

    # --- Negative cases ---
    def test_pytorch_model_eval(self) -> None:
        src = "model = torch.nn.Linear(10, 2)\nmodel.eval()\n"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_custom_object_eval_method(self) -> None:
        src = "class Evaluator:\n    def eval(self):\n        pass\ne = Evaluator()\ne.eval()\n"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_eval_function_definition(self) -> None:
        src = "def eval(arg):\n    return arg\n"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_ast_literal_eval_safe(self) -> None:
        src = "import ast\nres = ast.literal_eval('[1, 2, 3]')\n"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_eval_variable_assignment(self) -> None:
        src = "eval_mode = True\neval = 42\n"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    # --- Edge cases ---
    def test_multiple_eval_calls(self) -> None:
        src = "eval('1')\nprint('ok')\neval('2')\n"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 2
        assert findings[0].line == 1
        assert findings[1].line == 3
