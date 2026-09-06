# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-06

### Added
- **Dependency Security Subsystem (`pyshield.dependencies`)**:
  - Deterministic parsers for `requirements.txt` (PEP 508), `pyproject.toml` (PEP 621 / PEP 735 `dependency-groups`), and `uv.lock`.
  - Normalized `Dependency` and `Vulnerability` data models.
  - Multi-source dependency deduplication prioritizing resolved exact versions from `uv.lock`.
  - OSV (Open Source Vulnerabilities) intelligence provider using standard library `urllib.request` with zero third-party dependencies, safe timeouts, and response buffer limits.
  - Graceful network error and offline resilience reporting controlled diagnostics (`VulnerabilityLookupUnavailable` / `OfflineMode`) without crashing or creating misleading safe findings.
- **Dependency Security Rules (Phase 3)**:
  - `PS801`: Known Vulnerable Dependency detection via OSV ecosystem queries with CVE/GHSA aliases and version-specific remediation.
  - `PS802`: Unpinned Dependency detection for unconstrained declarations in `requirements.txt` and `pyproject.toml` (exempts `uv.lock`).
- **Security Configuration Rules (Phase 3)**:
  - `PS701`: Debug Mode Enabled (`DEBUG = True` / `1`) detection (CWE-489).
  - `PS702`: Insecure TLS Certificate Verification Disabled (`verify=False` / `0` / `None`) in HTTP client calls (CWE-295).
  - `PS703`: Insecure Cookie Configuration (`SESSION_COOKIE_SECURE = False`, etc.) detection (CWE-614).
  - `PS704`: Insecure Host / Origin Wildcard (`ALLOWED_HOSTS = ["*"]`, `CORS_ALLOW_ALL_ORIGINS = True`) detection (CWE-346).
- **CLI & Orchestration**:
  - Added `--offline` flag to `pyshield scan` to allow local-only analysis without external network calls.
  - `ScanEngine` automatically discovers and parses dependency files alongside Python source files.
- **Testing & Quality**:
  - 68 new unit and integration tests (223 tests total) maintaining >93% coverage.

## [0.1.0] - 2026-09-06

### Added
- **Core Static Security Analysis Engine**:
  - Deterministic Python `ast`-based analyzer with graceful syntax error and decode recovery.
  - Safe recursive file discovery respecting ignore patterns (`.git`, `.venv`, `__pycache__`) and symlink cycles.
  - Extensible `RuleRegistry` and `BaseRule` architecture.
  - Decoupled terminal reporting using `rich`.
  - Developer-friendly CLI via `typer` (`pyshield scan`, `pyshield --version`).
  - Standardized exit codes (`0` clean, `1` findings detected, `2` fatal error).
- **Execution & Injection Security Rules (Phase 1)**:
  - `PS101`: Dangerous `eval()` usage detection (CWE-95).
  - `PS102`: Dangerous `exec()` usage detection (CWE-95).
  - `PS103`: Dangerous `os.system()` usage detection (CWE-78).
  - `PS104`: Unsafe `subprocess` execution with `shell=True` (CWE-78).
- **Secret Detection & Cryptography Analysis Rules (Phase 2)**:
  - `PS201`: Hardcoded Secret / Credential detection with contextual identifier matching, Shannon entropy analysis, and placeholder filtering.
  - `PS202`: Private Key Material detection for RSA, EC, DSA, and OpenSSH private key PEM blocks.
  - `PS203`: High-confidence API Token detection with specific patterns for AWS, GitHub (classic and fine-grained PATs), Slack, Google, and Stripe.
  - `PS301`: Weak Cryptographic Hash detection for MD5 and SHA-1 via `hashlib` (properly exempts `usedforsecurity=False`).
  - `PS302`: Insecure Cryptographic Algorithm detection for broken legacy ciphers (DES, 3DES, Blowfish, ARC4) across `cryptography` and `Crypto.Cipher`.
  - `PS303`: Insecure Randomness detection for pseudo-random standard library `random` module usage in security-sensitive scopes (tokens, passwords, keys, salts).
  - Shared secrets utility module (`secrets_utils.py`) with Shannon entropy, placeholder recognition, and sensitive token masking.
  - Strict secret leakage prevention guaranteeing detected secrets never appear in finding messages, descriptions, snippets, logs, or terminal reports.
- **Testing & Quality**:
  - Complete test suite with 155 unit and integration tests achieving >94% line coverage.
  - Strict typing (Mypy strict mode) and Ruff linting/formatting.
