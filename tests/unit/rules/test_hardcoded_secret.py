"""Tests for PS201: Hardcoded secret / credential rule."""

from tests.conftest import make_context

from pyshield.core.models import Severity
from pyshield.reporters.terminal import TerminalReporter
from pyshield.rules.builtin.hardcoded_secret import HardcodedSecretRule


class TestHardcodedSecretRule:
    def setup_method(self) -> None:
        self.rule = HardcodedSecretRule()

    # --- Positive cases ---
    def test_direct_password_assignment(self) -> None:
        fake_pass = "xK9#mQ2$pL8!vR5&"
        src = f'PASSWORD = "{fake_pass}"'
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "PS201"
        assert f.severity == Severity.HIGH
        assert f.cwe == "CWE-798"
        assert f.line == 1

        # Strict Secret Leakage Verification
        assert fake_pass not in f.message
        assert fake_pass not in f.description
        assert f.snippet is not None
        assert fake_pass not in f.snippet
        assert "*" in f.snippet

    def test_annotated_api_key_assignment(self) -> None:
        fake_key = "prod_api_key_998877665544332211"
        src = f'API_KEY: str = "{fake_key}"'
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert fake_key not in findings[0].message
        assert fake_key not in (findings[0].snippet or "")

    def test_dictionary_credential_assignment(self) -> None:
        fake_secret = "Jk8#vN2$zW9!mQ4&"
        src = f'config = {{"client_secret": "{fake_secret}"}}'
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert fake_secret not in findings[0].message
        assert fake_secret not in (findings[0].snippet or "")

    def test_multiline_dictionary_credential_assignment(self) -> None:
        fake_secret = "M9#xL2$vR8!pQ5&w"
        src = f"""config = {{
    "host": "localhost",
    "password": "{fake_secret}",
}}"""
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        f = findings[0]
        assert f.line == 3
        assert fake_secret not in f.message
        assert fake_secret not in (f.snippet or "")
        assert "password" in (f.snippet or "")
        assert "*" in (f.snippet or "")

    def test_multiline_string_credential_assignment(self) -> None:
        fake_part = "secret_part_12345"
        src = f'PASSWORD = """{fake_part}\nsecond_line_67890"""'
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        f = findings[0]
        assert fake_part not in f.message
        assert fake_part not in (f.snippet or "")
        assert "*" in (f.snippet or "")

    # --- Negative / Placeholder cases ---
    def test_common_placeholder_values_ignored(self) -> None:
        src = """
PASSWORD = "password"
ADMIN_PASS = "changeme"
API_KEY = "your-api-key"
SECRET = "<insert-secret-here>"
TOKEN = "${AUTH_TOKEN}"
DUMMY = "example-token-123"
        """
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_environment_variable_lookups_ignored(self) -> None:
        src = """
import os
PASSWORD = os.getenv("DB_PASSWORD")
API_KEY = os.environ["API_KEY"]
TOKEN = os.environ.get("AUTH_TOKEN")
        """
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_empty_or_none_ignored(self) -> None:
        src = """
PASSWORD = ""
API_KEY = None
SECRET = False
        """
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_urls_and_paths_ignored(self) -> None:
        src = """
API_KEY_URL = "https://api.example.com/v1/keys"
SECRET_FILE_PATH = "/etc/ssl/certs/app.crt"
        """
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_unrelated_variable_names_ignored(self) -> None:
        src = """
tokenizer = "bert-base-uncased-model-12345"
public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB"
        """
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    # --- Secret Leakage in Rendered Report ---
    def test_no_secret_in_rendered_terminal_output(self) -> None:
        from pyshield.core.models import ScanResult, ScanSummary

        fake_val = "pAssw0rd_987654321_secret!"
        src = f'PASSWORD = "{fake_val}"'
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1

        result = ScanResult(
            findings=findings,
            diagnostics=[],
            summary=ScanSummary(files_scanned=1, findings_count={Severity.HIGH: 1}),
        )
        reporter = TerminalReporter()
        report_output = reporter.render_to_string(result)

        # The fake secret must NEVER appear in the terminal output
        assert fake_val not in report_output
        assert "PS201" in report_output
