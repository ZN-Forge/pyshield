"""Tests for PS301: Weak hash algorithm rule."""

from tests.conftest import make_context

from pyshield.core.models import Confidence, Severity
from pyshield.rules.builtin.weak_hash import WeakHashRule


class TestWeakHashRule:
    def setup_method(self) -> None:
        self.rule = WeakHashRule()

    # --- Positive cases ---
    def test_hashlib_md5_direct(self) -> None:
        src = "import hashlib\nh = hashlib.md5(b'data')"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "PS301"
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.HIGH
        assert f.cwe == "CWE-328"
        assert "MD5" in f.message

    def test_hashlib_sha1_direct(self) -> None:
        src = "import hashlib\nh = hashlib.sha1(b'data')"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert "SHA1" in findings[0].message

    def test_hashlib_new_md5(self) -> None:
        src = "import hashlib\nh = hashlib.new('md5', b'data')"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert "MD5" in findings[0].message

    def test_hashlib_new_sha1_kwarg(self) -> None:
        src = "import hashlib\nh = hashlib.new(name='sha1')"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1
        assert "SHA1" in findings[0].message

    def test_from_hashlib_import_md5(self) -> None:
        src = "from hashlib import md5\nh = md5(b'data')"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1

    def test_from_hashlib_import_sha1(self) -> None:
        src = "from hashlib import sha1\nh = sha1(b'data')"
        ctx = make_context(src)
        findings = self.rule.check(ctx)
        assert len(findings) == 1

    # --- Negative cases ---
    def test_hashlib_sha256_safe(self) -> None:
        src = "import hashlib\nh = hashlib.sha256(b'data')"
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    def test_hashlib_sha512_safe(self) -> None:
        src = "import hashlib\nh = hashlib.sha512(b'data')"
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    def test_hashlib_md5_usedforsecurity_false_safe(self) -> None:
        # Python 3.9+ feature for explicit non-security hashing (e.g. cache key, checksum)
        src = "import hashlib\nh = hashlib.md5(b'data', usedforsecurity=False)"
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    def test_hashlib_new_md5_usedforsecurity_false_safe(self) -> None:
        src = "import hashlib\nh = hashlib.new('md5', usedforsecurity=False)"
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0

    def test_custom_object_md5_method_ignored(self) -> None:
        src = """
class DataHasher:
    def md5(self):
        return "custom"
hasher = DataHasher()
hasher.md5()
        """
        ctx = make_context(src)
        assert len(self.rule.check(ctx)) == 0
