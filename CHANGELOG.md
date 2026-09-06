# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
