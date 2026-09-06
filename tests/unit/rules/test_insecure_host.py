"""Unit tests for PS704: InsecureHostRule."""

from pathlib import Path

from pyshield.core.analyzer import ASTAnalyzer
from pyshield.core.models import Severity
from pyshield.rules.builtin.insecure_host import InsecureHostRule


class TestInsecureHostRule:
    def setup_method(self) -> None:
        self.rule = InsecureHostRule()
        self.analyzer = ASTAnalyzer(rules=[self.rule])
        self.dummy_path = Path("test_settings.py")

    def test_allowed_hosts_wildcard_list(self) -> None:
        code = 'ALLOWED_HOSTS = ["*"]\n'
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 1
        assert findings[0].rule_id == "PS704"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].cwe == "CWE-346"

    def test_allowed_hosts_wildcard_tuple(self) -> None:
        code = 'ALLOWED_HOSTS = ("*",)\n'
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 1

    def test_allowed_hosts_wildcard_mixed(self) -> None:
        code = 'ALLOWED_HOSTS = ["api.example.com", "*"]\n'
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 1

    def test_annotated_allowed_hosts_wildcard(self) -> None:
        code = 'ALLOWED_HOSTS: list[str] = ["*"]\n'
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 1

    def test_cors_allow_all_origins_true(self) -> None:
        code = "CORS_ALLOW_ALL_ORIGINS = True\n"
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 1
        assert findings[0].rule_id == "PS704"

    def test_cors_origin_allow_all_true(self) -> None:
        code = "CORS_ORIGIN_ALLOW_ALL = True\n"
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 1

    def test_allowed_hosts_specific_domains_safe(self) -> None:
        code = 'ALLOWED_HOSTS = ["api.example.com", "localhost", "127.0.0.1"]\n'
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 0

    def test_cors_allow_all_origins_false_safe(self) -> None:
        code = "CORS_ALLOW_ALL_ORIGINS = False\n"
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 0

    def test_unrelated_wildcard_lists_safe(self) -> None:
        code = 'MATH_OPERATORS = ["*", "+", "-", "/"]\nALLOWED_FIELDS = ["*"]\n'
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 0
