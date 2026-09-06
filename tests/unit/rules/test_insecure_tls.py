"""Unit tests for PS702: InsecureTlsRule."""

from pathlib import Path

from pyshield.core.analyzer import ASTAnalyzer
from pyshield.core.models import Severity
from pyshield.rules.builtin.insecure_tls import InsecureTlsRule


class TestInsecureTlsRule:
    def setup_method(self) -> None:
        self.rule = InsecureTlsRule()
        self.analyzer = ASTAnalyzer(rules=[self.rule])
        self.dummy_path = Path("test_client.py")

    def test_requests_get_verify_false(self) -> None:
        code = 'import requests\nresp = requests.get("https://example.com", verify=False)\n'
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 1
        assert findings[0].rule_id == "PS702"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].cwe == "CWE-295"
        assert findings[0].line == 2

    def test_requests_post_verify_zero(self) -> None:
        code = 'import requests\nresp = requests.post("https://example.com", data={}, verify=0)\n'
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 1

    def test_requests_verify_none(self) -> None:
        code = 'import requests\nresp = requests.get("https://example.com", verify=None)\n'
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 1

    def test_httpx_get_verify_false(self) -> None:
        code = 'import httpx\nresp = httpx.get("https://example.com", verify=False)\n'
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 1

    def test_session_get_verify_false(self) -> None:
        code = (
            "import requests\n"
            "session = requests.Session()\n"
            'resp = session.get("https://example.com", verify=False)\n'
        )
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 1

    def test_from_requests_import_get_verify_false(self) -> None:
        code = 'from requests import get\nresp = get("https://example.com", verify=False)\n'
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 1

    def test_requests_get_verify_true_safe(self) -> None:
        code = 'import requests\nresp = requests.get("https://example.com", verify=True)\n'
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 0

    def test_requests_get_default_verify_safe(self) -> None:
        code = 'import requests\nresp = requests.get("https://example.com")\n'
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 0

    def test_unrelated_function_verify_false_safe(self) -> None:
        code = (
            "def check_credential(cred, verify=False):\n"
            "    return verify\n"
            'check_credential("test", verify=False)\n'
        )
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 0

    def test_requests_session_chained_call(self) -> None:
        code = (
            'import requests\nresp = requests.Session().get("https://example.com", verify=False)\n'
        )
        findings, diag = self.analyzer.analyze_source(code, self.dummy_path)
        assert diag is None
        assert len(findings) == 1
