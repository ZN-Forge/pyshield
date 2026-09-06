"""Tests for PS302: Insecure cryptographic algorithm rule."""

from tests.conftest import make_context

from pyshield.core.models import Confidence, Severity
from pyshield.rules.builtin.insecure_crypto import InsecureCryptoRule


class TestInsecureCryptoRule:
    def setup_method(self) -> None:
        self.rule = InsecureCryptoRule()

    # --- Positive cases ---
    def test_pycryptodome_des_new(self) -> None:
        src = "from Crypto.Cipher import DES\ncipher = DES.new(b'12345678')"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "PS302"
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH
        assert f.cwe == "CWE-327"
        assert "DES" in f.message

    def test_pycryptodome_arc4_new(self) -> None:
        src = "from Crypto.Cipher import ARC4\ncipher = ARC4.new(b'secretkey')"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert "ARC4" in findings[0].message

    def test_pycryptodome_des3_new(self) -> None:
        src = "from Crypto.Cipher import DES3\ncipher = DES3.new(b'1234567812345678')"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert "DES3" in findings[0].message

    def test_cryptography_tripledes(self) -> None:
        src = (
            "from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES\n"
            "algo = TripleDES(b'1234567812345678')"
        )
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert "TripleDES" in findings[0].message

    def test_cryptography_arc4(self) -> None:
        src = (
            "from cryptography.hazmat.primitives.ciphers.algorithms import ARC4\n"
            "algo = ARC4(b'secret_key_bytes')"
        )
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert "ARC4" in findings[0].message

    def test_pydes_des(self) -> None:
        src = "from pyDes import des\nd = des(b'DESCRYPT')"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1

    # --- Negative cases ---
    def test_aes_cipher_safe(self) -> None:
        src = "from Crypto.Cipher import AES\ncipher = AES.new(b'1234567890123456', AES.MODE_GCM)"
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    def test_cryptography_aes_safe(self) -> None:
        src = (
            "from cryptography.hazmat.primitives.ciphers.algorithms import AES\n"
            "algo = AES(b'1234567890123456')"
        )
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    def test_unrelated_custom_des_class_ignored(self) -> None:
        # Not imported from Crypto.Cipher -> ignored
        src = """
class DES:
    @staticmethod
    def new(key):
        return "mock"
cipher = DES.new(b'data')
        """
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    def test_unrelated_variable_name_ignored(self) -> None:
        src = 'DESCRIPTION = "Detailed system description"'
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0
