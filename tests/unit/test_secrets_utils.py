"""Unit tests for secret detection utilities."""

from pyshield.rules.secrets_utils import (
    is_placeholder,
    is_suspicious_credential_name,
    mask_secret,
    mask_snippet,
    shannon_entropy,
)


class TestSecretUtils:
    def test_placeholder_detection(self) -> None:
        # Positive cases (placeholders)
        assert is_placeholder("changeme")
        assert is_placeholder("PASSWORD")
        assert is_placeholder("your-api-key")
        assert is_placeholder("YOUR_API_KEY")
        assert is_placeholder("<insert_api_key_here>")
        assert is_placeholder("${DATABASE_PASSWORD}")
        assert is_placeholder("{{SECRET_KEY}}")
        assert is_placeholder("xxxxxxxxxxxxxxxxxxxx")
        assert is_placeholder("0000000000")
        assert is_placeholder("example-token-123")
        assert is_placeholder("dummy_key")
        assert is_placeholder("")
        assert is_placeholder("   ")

        # Negative cases (actual secret-looking strings)
        assert not is_placeholder("k8s_s3cr3t_p@ssw0rd_987654321")
        assert not is_placeholder("n7X#92Lz@qP!vR8$mK4w")

    def test_mask_secret_redacts_sensitive_content(self) -> None:
        prefix = "AKIA"
        suffix = "1234567890ABCDEF"
        fake_secret = f"{prefix}{suffix}"
        masked = mask_secret(fake_secret)

        # Confirm original sensitive suffix is absent
        assert "1234567890ABCDEF" not in masked
        assert masked.startswith("AKIA")
        assert "*" in masked

    def test_mask_secret_short(self) -> None:
        short_val = "secret"
        masked = mask_secret(short_val)
        assert "secret" not in masked
        assert masked == "********"

    def test_mask_snippet(self) -> None:
        raw_secret = "super_secret_token_12345"
        raw_line = f'AUTH_TOKEN = "{raw_secret}"'
        masked_line = mask_snippet(raw_line, raw_secret)

        assert raw_secret not in masked_line
        assert "AUTH_TOKEN" in masked_line
        assert "*" in masked_line

    def test_mask_snippet_multiline(self) -> None:
        raw_secret = "part_one_secret\npart_two_secret"
        raw_line = 'TOKEN = """part_one_secret'
        masked_line = mask_snippet(raw_line, raw_secret)

        assert "part_one_secret" not in masked_line
        assert "*" in masked_line

    def test_mask_snippet_escaped_fallback(self) -> None:
        raw_line = 'PASS = "escaped\\"secret12345"'
        secret = 'escaped"secret12345'
        masked_line = mask_snippet(raw_line, secret)

        assert "secret12345" not in masked_line
        assert "*" in masked_line

    def test_shannon_entropy(self) -> None:
        assert shannon_entropy("") == 0.0
        # Repetitive string has low entropy (0.0 for 1 character)
        assert shannon_entropy("aaaaaaaa") == 0.0
        # Normal lowercase English word has moderate entropy
        assert 1.0 < shannon_entropy("hello") < 3.0
        # Random complex string has high entropy
        assert shannon_entropy("aB9#kL2$mQ8!zW5&") > 3.5

    def test_suspicious_credential_name(self) -> None:
        assert is_suspicious_credential_name("password")
        assert is_suspicious_credential_name("DB_PASSWORD")
        assert is_suspicious_credential_name("api_key")
        assert is_suspicious_credential_name("SECRET_KEY")
        assert is_suspicious_credential_name("auth_token")
        assert is_suspicious_credential_name("client_secret")

        # Negative cases: non-credential terms
        assert not is_suspicious_credential_name("public_key")
        assert not is_suspicious_credential_name("key_id")
        assert not is_suspicious_credential_name("tokenizer")
        assert not is_suspicious_credential_name("keyboard")
        assert not is_suspicious_credential_name("token_type")
