"""Tests for PS202: Private key material rule."""

from tests.conftest import make_context

from pyshield.core.models import ScanResult, ScanSummary, Severity
from pyshield.reporters.terminal import TerminalReporter
from pyshield.rules.builtin.private_key import PrivateKeyRule


class TestPrivateKeyRule:
    def setup_method(self) -> None:
        self.rule = PrivateKeyRule()

    # --- Positive cases ---
    def test_detects_generic_private_key(self) -> None:
        fake_key_body = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD"
        src = f'KEY = """-----BEGIN PRIVATE KEY-----\n{fake_key_body}\n-----END PRIVATE KEY-----"""'
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "PS202"
        assert f.severity == Severity.CRITICAL
        assert f.cwe == "CWE-312"

        # Leakage check: actual key body must not appear
        assert fake_key_body not in f.message
        assert fake_key_body not in f.description
        assert fake_key_body not in (f.snippet or "")

    def test_detects_private_key_multiline_offset(self) -> None:
        src = '''DOC = """
Some header
-----BEGIN RSA PRIVATE KEY-----
fake_body
-----END RSA PRIVATE KEY-----
"""'''
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert findings[0].line == 3
        assert findings[0].snippet == "-----BEGIN [REDACTED PRIVATE KEY]-----"

    def test_detects_rsa_private_key(self) -> None:
        src = (
            'RSA_KEY = "-----BEGIN RSA PRIVATE KEY-----\\n'
            'fake_body\\n-----END RSA PRIVATE KEY-----"'
        )
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1

    def test_detects_ec_private_key(self) -> None:
        src = 'EC_KEY = "-----BEGIN EC PRIVATE KEY-----\\nfake_body\\n-----END EC PRIVATE KEY-----"'
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1

    def test_detects_openssh_private_key(self) -> None:
        src = (
            'SSH_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\\n'
            'fake_body\\n-----END OPENSSH PRIVATE KEY-----"'
        )
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1

    def test_detects_dsa_private_key(self) -> None:
        src = (
            'DSA_KEY = "-----BEGIN DSA PRIVATE KEY-----\\n'
            'fake_body\\n-----END DSA PRIVATE KEY-----"'
        )
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1

    # --- Negative cases ---
    def test_public_key_ignored(self) -> None:
        src = (
            'PUB_KEY = "-----BEGIN PUBLIC KEY-----\\n'
            'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\\n-----END PUBLIC KEY-----"'
        )
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_certificate_ignored(self) -> None:
        src = 'CERT = "-----BEGIN CERTIFICATE-----\\nMIICljCCAX4CCQDK\\n-----END CERTIFICATE-----"'
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    def test_unrelated_text_ignored(self) -> None:
        src = 'doc = "This function uses a private key stored in HSM."'
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 0

    # --- Secret Leakage in Rendered Terminal Output ---
    def test_no_key_leakage_in_terminal_output(self) -> None:
        secret_content = "FAKE_BASE64_PRIVATE_KEY_BYTES_DO_NOT_LEAK"
        src = (
            f'KEY = "-----BEGIN RSA PRIVATE KEY-----\\n'
            f'{secret_content}\\n-----END RSA PRIVATE KEY-----"'
        )
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1

        result = ScanResult(
            findings=findings,
            diagnostics=[],
            summary=ScanSummary(files_scanned=1, findings_count={Severity.CRITICAL: 1}),
        )
        reporter = TerminalReporter()
        output = reporter.render_to_string(result)

        assert secret_content not in output
        assert "[REDACTED PRIVATE KEY]" in output
