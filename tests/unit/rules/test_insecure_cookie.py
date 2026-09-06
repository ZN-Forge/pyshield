"""Unit tests for PS703: InsecureCookieRule."""

from pathlib import Path

from pyshield.core.analyzer import ASTAnalyzer
from pyshield.core.models import Severity
from pyshield.rules.builtin.insecure_cookie import InsecureCookieRule


class TestInsecureCookieRule:
    def setup_method(self) -> None:
        self.rule = InsecureCookieRule()
        self.analyzer = ASTAnalyzer(rules=[self.rule])
        self.dummy_path = Path("test_settings.py")

    def test_session_cookie_secure_false(self) -> None:
        code = "SESSION_COOKIE_SECURE = False\n"
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 1
        assert findings[0].rule_id == "PS703"
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].cwe == "CWE-614"

    def test_csrf_cookie_secure_false(self) -> None:
        code = "CSRF_COOKIE_SECURE = False\n"
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 1
        assert findings[0].rule_id == "PS703"

    def test_session_cookie_httponly_false(self) -> None:
        code = "SESSION_COOKIE_HTTPONLY = False\n"
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 1
        assert findings[0].rule_id == "PS703"

    def test_annotated_cookie_setting(self) -> None:
        code = "SESSION_COOKIE_SECURE: bool = False\n"
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 1

    def test_secure_cookies_true_safe(self) -> None:
        code = (
            "SESSION_COOKIE_SECURE = True\n"
            "CSRF_COOKIE_SECURE = True\n"
            "SESSION_COOKIE_HTTPONLY = True\n"
        )
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 0

    def test_unrelated_cookie_var_safe(self) -> None:
        code = "MY_COOKIE_SECURE = False\n"
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 0
