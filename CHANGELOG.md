# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Phase 2 — Secret Detection & Cryptography Analysis**:
  - `PS201`: Hardcoded Secret / Credential detection with contextual identifier matching, Shannon entropy analysis, and dummy/placeholder filtering.
  - `PS202`: Private Key Material detection for RSA, EC, DSA, and OpenSSH private key PEM blocks.
  - `PS203`: High-confidence API Token detection with specific patterns for AWS, GitHub (classic and fine-grained PATs), Slack, Google, and Stripe.
  - `PS301`: Weak Cryptographic Hash detection for MD5 and SHA-1 via `hashlib` (properly exempts `usedforsecurity=False`).
  - `PS302`: Insecure Cryptographic Algorithm detection for broken legacy ciphers (DES, 3DES, Blowfish, ARC4) across `cryptography` and `Crypto.Cipher`.
  - `PS303`: Insecure Randomness detection for pseudo-random standard library `random` module usage in security-sensitive scopes (tokens, passwords, keys, salts).
  - Shared secrets utility module (`secrets_utils.py`) with Shannon entropy, placeholder recognition, and sensitive token masking.
  - Strict secret leakage prevention guaranteeing detected secrets never appear in finding messages, descriptions, snippets, logs, or terminal reports.
  - Unit and integration tests expanding test suite to 149 tests with 94.66% coverage.

## [0.1.0] - 2026-09-06

### Added
- Phase 1 core architecture and static security analysis foundation.
- Python `ast`-based analyzer with non-crashing syntax error handling.
- Extensible `RuleRegistry` and `BaseRule` interface.
- Initial security rules:
  - `PS101`: Dangerous `eval()` usage detection (CWE-95).
  - `PS102`: Dangerous `exec()` usage detection (CWE-95).
  - `PS103`: Dangerous `os.system()` usage detection (CWE-78).
  - `PS104`: Unsafe `subprocess` execution with `shell=True` (CWE-78).
- Recursive file discovery respecting common ignore patterns (`.git`, `.venv`, `__pycache__`, etc.) and symlink cycles.
- Decoupled terminal reporter using `rich`.
- Developer-friendly CLI via `typer` (`pyshield scan`, `pyshield --version`).
- Standardized exit codes (0 = clean, 1 = findings detected, 2 = scan error).
- Comprehensive test suite and quality gates (Ruff, Mypy, Pytest).
