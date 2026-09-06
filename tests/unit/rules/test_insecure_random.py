"""Tests for PS303: Insecure randomness in security-sensitive context rule."""

from tests.conftest import make_context

from pyshield.core.models import Confidence, Severity
from pyshield.rules.builtin.insecure_random import InsecureRandomRule


class TestInsecureRandomRule:
    def setup_method(self) -> None:
        self.rule = InsecureRandomRule()

    # --- Positive cases ---
    def test_random_token_assignment(self) -> None:
        src = "import random\nauth_token = str(random.random())"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "PS303"
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH
        assert f.cwe == "CWE-330"
        assert "auth_token" in f.message

    def test_random_session_id_assignment(self) -> None:
        src = "import random\nsession_id = random.randint(100000, 999999)"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert "session_id" in findings[0].message

    def test_random_otp_assignment(self) -> None:
        src = "from random import randint\notp = randint(1000, 9999)"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert "otp" in findings[0].message

    def test_security_function_returning_random(self) -> None:
        src = """
import random
def generate_password():
    chars = "abcdef012345"
    return "".join(random.choice(chars) for _ in range(12))
        """
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert "generate_password" in findings[0].message

    # --- Negative / Non-security cases ---
    def test_random_shuffle_safe(self) -> None:
        src = """
import random
deck = [1, 2, 3, 4, 5]
random.shuffle(deck)
        """
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    def test_random_simulation_safe(self) -> None:
        src = """
import random
dice_roll = random.randint(1, 6)
selected_color = random.choice(["red", "blue", "green"])
        """
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    def test_non_security_function_returning_random_safe(self) -> None:
        src = """
import random
def roll_dice():
    return random.randint(1, 6)
        """
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    def test_secrets_module_safe(self) -> None:
        src = """
import secrets
token = secrets.token_hex(32)
otp = secrets.randbelow(10000)
        """
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0
