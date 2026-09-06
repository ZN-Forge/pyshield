"""Tests for PS203: High-confidence API token rule."""

from tests.conftest import make_context

from pyshield.core.models import ScanResult, ScanSummary, Severity
from pyshield.reporters.terminal import TerminalReporter
from pyshield.rules.builtin.api_token import ApiTokenRule


class TestApiTokenRule:
    def setup_method(self) -> None:
        self.rule = ApiTokenRule()

    # --- AWS Access Key Tests ---
    def test_aws_access_key_positive(self) -> None:
        prefix = "AKIA"
        suffix = "3N4P5Q6R7S8T9U0V"
        fake_aws = f"{prefix}{suffix}"
        src = f'AWS_KEY = "{fake_aws}"'
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert "AWS Access Key ID" in findings[0].message
        assert fake_aws not in findings[0].message
        assert fake_aws not in (findings[0].snippet or "")

    def test_aws_access_key_placeholder(self) -> None:
        src = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    def test_aws_access_key_malformed(self) -> None:
        # Too short (only 10 chars instead of 20)
        src = 'AWS_KEY = "AKIA123456"'
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    # --- GitHub Token Tests ---
    def test_github_pat_positive(self) -> None:
        prefix = "ghp_"
        suffix = "1234567890abcdefghijklmnopqrstuvwxyz"
        fake_gh = f"{prefix}{suffix}"
        src = f'GITHUB_TOKEN = "{fake_gh}"'
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert "GitHub Personal Access Token" in findings[0].message
        assert fake_gh not in (findings[0].snippet or "")

    def test_github_pat_placeholder(self) -> None:
        prefix = "ghp_"
        src = f'GITHUB_TOKEN = "{prefix}{"x" * 36}"'
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    def test_github_pat_malformed(self) -> None:
        prefix = "ghp_"
        src = f'GITHUB_TOKEN = "{prefix}short"'
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    def test_github_fine_grained_pat_positive(self) -> None:
        prefix = "github_pat_"
        # 82 chars after prefix
        suffix = (
            "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_abcdefghij"
        )
        fake_fine_grained = f"{prefix}{suffix}"
        src = f'TOKEN = "{fake_fine_grained}"'
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert "GitHub Fine-Grained" in findings[0].message

    def test_token_in_multiline_string(self) -> None:
        prefix = "AKIA"
        suffix = "9988776655443322"
        fake_aws = f"{prefix}{suffix}"
        src = f'''DOC = """
Some header documentation.
aws_access_key_id = "{fake_aws}"
More notes.
"""'''
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        f = findings[0]
        assert f.line == 3
        assert fake_aws not in f.message
        assert fake_aws not in (f.snippet or "")
        assert "AKIA****************" in (f.snippet or "")

    # --- Slack Token Tests ---
    def test_slack_token_positive(self) -> None:
        parts = ["xoxb", "123456789012", "987654321098", "abcdefghijklmno"]
        fake_slack = "-".join(parts)
        src = f'SLACK_BOT_TOKEN = "{fake_slack}"'
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert "Slack Token" in findings[0].message
        assert fake_slack not in (findings[0].snippet or "")

    def test_slack_token_placeholder(self) -> None:
        prefix = "xoxb"
        src = f'SLACK_TOKEN = "{prefix}-xxxxxxxxxxxx-xxxxxxxxxxxx-xxxxxxxx"'
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    def test_slack_token_malformed(self) -> None:
        prefix = "xoxb"
        src = f'SLACK_TOKEN = "{prefix}-123-short"'
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    # --- Google API Key Tests ---
    def test_google_api_key_positive(self) -> None:
        prefix = "AIza"
        suffix = "SyD1234567890abcdefghijklmnopqr"
        fake_google = f"{prefix}{suffix}"
        src = f'GOOGLE_KEY = "{fake_google}"'
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert "Google API Key" in findings[0].message
        assert fake_google not in (findings[0].snippet or "")

    def test_google_api_key_placeholder(self) -> None:
        prefix = "AIza"
        src = f'GOOGLE_KEY = "{prefix}{"x" * 35}"'
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    def test_google_api_key_malformed(self) -> None:
        prefix = "AIza"
        src = f'GOOGLE_KEY = "{prefix}Short"'
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    # --- Stripe Secret Key Tests ---
    def test_stripe_secret_key_positive(self) -> None:
        prefix = "sk_test_"
        suffix = "51A2B3C4D5E6F7G8H9I0J1K2L3M"
        fake_stripe = f"{prefix}{suffix}"
        src = f'STRIPE_KEY = "{fake_stripe}"'
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert "Stripe Secret Key" in findings[0].message
        assert fake_stripe not in (findings[0].snippet or "")

    def test_stripe_secret_key_placeholder(self) -> None:
        prefix = "sk_test_"
        src = f'STRIPE_KEY = "{prefix}{"x" * 24}"'
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    def test_stripe_secret_key_malformed(self) -> None:
        prefix = "sk_test_"
        src = f'STRIPE_KEY = "{prefix}short"'
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    # --- Generic strings should NOT be flagged as API tokens ---
    def test_generic_random_string_not_flagged(self) -> None:
        src = 'DATA = "c0a80101f3e2d1c0b9a876543210fedcba987654"'
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    # --- Leakage check in rendered output ---
    def test_token_not_leaked_in_terminal_output(self) -> None:
        prefix = "AKIA"
        suffix = "9876543210ZYXWVU"
        token = f"{prefix}{suffix}"
        src = f'KEY = "{token}"'
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1

        result = ScanResult(
            findings=findings,
            diagnostics=[],
            summary=ScanSummary(files_scanned=1, findings_count={Severity.HIGH: 1}),
        )
        reporter = TerminalReporter()
        report = reporter.render_to_string(result)

        assert token not in report
        assert "AKIA****************" in report
