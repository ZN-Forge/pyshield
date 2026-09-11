# PyShield

[![CI](https://github.com/ZN-Forge/pyshield/actions/workflows/ci.yml/badge.svg)](https://github.com/ZN-Forge/pyshield/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/pyshield-security.svg)](https://pypi.org/project/pyshield-security/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Managed with uv](https://img.shields.io/badge/managed%20with-uv-blueviolet.svg)](https://docs.astral.sh/uv/)

**PyShield** is a developer-focused, open-source static security analysis platform for Python projects, maintained under the [**ZN-Forge**](https://github.com/ZN-Forge) organization.

Its primary purpose is to help developers identify potential security vulnerabilities in their code before reaching production through fast, deterministic AST analysis.

---

> [!NOTE]
> **Current Status: [![PyPI version](https://img.shields.io/pypi/v/pyshield-security.svg)](https://pypi.org/project/pyshield-security/) (Production Release)**
> PyShield delivers a complete deterministic security suite: AST-based static analysis, injection prevention (`PS10x`), secret masking (`PS20x`), cryptography auditing (`PS30x`), configuration security (`PS70x`), dependency vulnerability & pinning analysis (`PS80x`) with offline support, and automated GitHub Release to PyPI publishing via OIDC Trusted Publishing. Future capabilities (SARIF export, React UI, etc.) are planned for upcoming releases.

---

## Core Philosophy

1. **Deterministic-First**: Security detection is powered primarily by deterministic AST analysis and strict rules. Findings are verifiable and reproducible.
2. **Local-First & Privacy-Focused**: Source code is analyzed entirely on your local machine and is never transmitted to external services.
3. **Secret Protection by Design**: Detected secret values and key material are masked in terminal reports and findings to prevent credential exposure.
4. **Core Decoupling**: The static security analysis engine is strictly decoupled from presentation, web server, and persistence layers.
5. **Minimal Dependencies**: The core analysis leverages Python's built-in `ast` and standard library to remain fast, lightweight, and maintainable without heavy external HTTP or dependency frameworks.
6. **Zero False-Positive Focus**: Rules are designed conservatively to highlight high-confidence security hazards without flooding developers with noise.

---

## Supported Rules

### Execution & Code Injection (Phase 1)
| Rule ID | Name | Severity | CWE | Description |
| :--- | :--- | :--- | :--- | :--- |
| **`PS101`** | Dangerous `eval()` usage | `CRITICAL` | CWE-95 | Detects calls to built-in `eval()`, preventing dynamic code execution risks. |
| **`PS102`** | Dangerous `exec()` usage | `CRITICAL` | CWE-95 | Detects calls to built-in `exec()`, preventing dynamic statement execution vulnerabilities. |
| **`PS103`** | Use of `os.system()` | `HIGH` | CWE-78 | Detects calls to `os.system()` which execute commands via shell strings. |
| **`PS104`** | Unsafe `subprocess` execution | `HIGH` | CWE-78 | Detects subprocess execution calls configured with `shell=True`. |

### Secret & Key Material Detection (Phase 2)
| Rule ID | Name | Severity | CWE | Description |
| :--- | :--- | :--- | :--- | :--- |
| **`PS201`** | Hardcoded Secret / Credential | `HIGH` | CWE-798 | Detects hardcoded passwords, tokens, secrets, and API keys with entropy filtering and placeholder exclusion. |
| **`PS202`** | Private Key Material | `CRITICAL` | CWE-321 | Detects hardcoded RSA, EC, DSA, and OpenSSH private key PEM headers and content. |
| **`PS203`** | High-Confidence API Token | `HIGH` | CWE-798 | Detects provider-specific tokens (AWS, GitHub classic/fine-grained, Slack, Google, Stripe) using strict patterns. |

### Cryptographic Analysis (Phase 2)
| Rule ID | Name | Severity | CWE | Description |
| :--- | :--- | :--- | :--- | :--- |
| **`PS301`** | Weak Hash Algorithm | `MEDIUM` | CWE-328 | Detects insecure MD5 and SHA-1 hashing via `hashlib` (exempts `usedforsecurity=False`). |
| **`PS302`** | Insecure Cryptographic Algorithm | `HIGH` | CWE-327 | Detects broken legacy ciphers (DES, 3DES, Blowfish, ARC4) in `cryptography` and PyCryptodome. |
| **`PS303`** | Insecure Randomness | `HIGH` | CWE-338 | Detects use of standard pseudo-random `random` module in security-sensitive contexts (tokens, salts, keys, auth). |

### Configuration Security (Phase 3)
| Rule ID | Name | Severity | CWE | Description |
| :--- | :--- | :--- | :--- | :--- |
| **`PS701`** | Debug Mode Enabled | `HIGH` | CWE-489 | Detects `DEBUG = True` enabled in configuration settings, exposing internal state and traces. |
| **`PS702`** | Insecure TLS Verification | `HIGH` | CWE-295 | Detects HTTP client calls disabling TLS certificate verification (`verify=False`). |
| **`PS703`** | Insecure Cookie Configuration | `MEDIUM` | CWE-614 | Detects disabled secure cookie transmission (`SESSION_COOKIE_SECURE = False`, etc.). |
| **`PS704`** | Insecure Host / Origin Wildcard | `HIGH` | CWE-346 | Detects wildcard host/CORS origins (`ALLOWED_HOSTS = ["*"]`, `CORS_ALLOW_ALL_ORIGINS = True`). |

### Dependency Security (Phase 3)
| Rule ID | Name | Severity | CWE | Description |
| :--- | :--- | :--- | :--- | :--- |
| **`PS801`** | Known Vulnerable Dependency | `HIGH` | CWE-1395 | Identifies dependencies with known published vulnerabilities via the OSV database. |
| **`PS802`** | Unpinned Dependency | `MEDIUM` | CWE-1104 | Detects dependencies declared without meaningful version constraints in `requirements.txt` / `pyproject.toml`. |

---

## Supported Dependency Sources

PyShield automatically discovers and analyzes the following dependency sources:
- **`requirements.txt`** (and `requirements*.txt`): Line-by-line PEP 508 parsing with comment and environment marker support.
- **`pyproject.toml`**: Standard PEP 621 `[project.dependencies]`, `[project.optional-dependencies]`, and `[dependency-groups]`.
- **`uv.lock`**: Precise resolved version verification (`uv.lock` is treated as the authoritative resolved source and is exempt from unpinned alerts).

---

## Installation

PyShield can be installed from PyPI using `pip` or `uv`:

```bash
# Using pip
pip install pyshield-security

# Using uv
uv add pyshield-security

# Or as a global CLI tool using uv:
uv tool install pyshield-security
```

> [!NOTE]
> The PyPI distribution package name is **`pyshield-security`**. The command-line command is **`pyshield`**, and the Python import package is **`pyshield`**:
> ```bash
> pyshield --version
> ```
> ```python
> import pyshield
> ```

---

## Development Setup

For local development or contributing, clone the repository and synchronize the isolated virtual environment using [`uv`](https://docs.astral.sh/uv/):

### Prerequisites
- Python 3.11 or higher
- `uv` package manager

### Setup
```bash
git clone https://github.com/ZN-Forge/pyshield.git
cd pyshield
uv sync
```

This creates a project-local `.venv/` containing all runtime and development dependencies locked in `uv.lock`.

---

## CLI Usage

### Check Version
```bash
# Direct CLI command (if installed via pip or uv tool):
pyshield --version

# Or inside the local development environment:
uv run pyshield --version
```

### Scan Current Directory
```bash
uv run pyshield scan .
```

### Scan Specific Directory or File
```bash
uv run pyshield scan src/
uv run pyshield scan app/main.py
```

### CLI Options

```bash
Usage: pyshield scan [OPTIONS] [PATHS]...

Arguments:
  [PATHS]...                    One or more paths to scan (default: current directory)

Options:
  --fail-on [LOW|MEDIUM|HIGH|CRITICAL]
                                Minimum severity to trigger non-zero exit code [default: LOW]
  -e, --exclude TEXT            Additional glob patterns or directories to exclude
  -d, --disable-rule TEXT       Rule ID to disable (e.g. -d PS101)
  --enable-rule TEXT            Explicit rule ID to run (e.g. --enable-rule PS103)
  --offline                     Run in offline mode without querying external vulnerability databases
  --help                        Show help message and exit
```

### Exit Codes
- `0`: Scan completed successfully; no findings at or above configured failure threshold.
- `1`: Security findings detected at or above configured failure threshold.
- `2`: Fatal error (target path not found, or all target files failed parsing).

---

## Development & Quality Gates

PyShield enforces strict quality gates before any code is merged:

```bash
# Run tests with coverage
uv run pytest --cov=pyshield --cov-report=term-missing

# Run Ruff linter
uv run ruff check .

# Run Ruff format check
uv run ruff format --check .

# Run strict type checking
uv run mypy src
```

---

## Release & Distribution

PyShield packages are published automatically to PyPI via **GitHub Actions** and **PyPI Trusted Publishing (OIDC)** whenever a new GitHub Release is created.

### Release Trigger & Security
- **Explicit Human Trigger**: Production releases are triggered **only** by publishing a new GitHub Release (`on: release: types: [published]`). Regular branch pushes, pull requests, and commits never publish to PyPI.
- **OIDC Trusted Publishing**: Authentication to PyPI uses short-lived cryptographic tokens via GitHub's OpenID Connect identity provider (`pypa/gh-action-pypi-publish`). No long-lived API tokens or passwords are saved as repository secrets.
- **Semantic Tag Synchronization**: Release tags must strictly follow `vMAJOR.MINOR.PATCH` (e.g. `v0.3.0`) and must match the package version in `pyproject.toml` and `src/pyshield/__init__.py`. If versions mismatch, the release workflow fails immediately before building.
- **Pre-Publish Verification**: The workflow runs complete code formatting, linting, strict typing, tests, builds clean wheel and sdist distributions, runs `twine check --strict`, and smoke-tests installation of the built wheel in an isolated environment.

### Developer Release Procedure
1. Update the version in `pyproject.toml` and `src/pyshield/__init__.py` (e.g., `0.3.0`).
2. Run the complete local quality gate:
   ```bash
   uv run python scripts/check.py
   ```
3. Commit and push the changes to `main`:
   ```bash
   git add pyproject.toml src/pyshield/__init__.py CHANGELOG.md
   git commit -m "chore: prepare v0.3.0 release"
   git push origin main
   ```
4. In GitHub, create and publish a new Release with tag `v0.3.0`.
5. The GitHub Actions release workflow (`.github/workflows/release.yml`) automatically executes the validation, build, and publishing pipeline.

### PyPI Trusted Publishing Configuration
Maintainers configure the trust relationship on PyPI under Project Settings:
- **PyPI Project**: `pyshield-security`
- **Owner**: `ZN-Forge`
- **Repository**: `pyshield`
- **Workflow Name**: `release.yml`
- **Environment**: *(leave empty)*

---

## Planned Architecture (Future Phases)

The following capabilities are deliberately planned for subsequent phases:

- **Phase 1 (Completed)**: Core static analysis engine, rule registry, injection rules (`PS101`–`PS104`), CLI, and terminal reporter.
- **Phase 2 (Completed)**: Secret detection engine (`PS201`–`PS203`) and Cryptography rules (`PS301`–`PS303`) with zero leakage protection.
- **Phase 3 (Completed)**: Dependency vulnerability scanning (`PS801`), pinning analysis (`PS802`), and Configuration security rules (`PS701`–`PS704`) with offline mode.
- **Phase 4 (Completed)**: Automated GitHub Release to PyPI distribution pipeline using OIDC Trusted Publishing and deterministic version validation.
- **Phase 5+**: Standard SARIF, JSON, and Markdown export formats.
- **Phase 6+**: Optional Local AI analysis layer (via Ollama / llama.cpp) to explain and contextualize deterministic findings.
- **Phase 7+**: Local Web UI (React + TypeScript + Vite + Tailwind CSS) with FastAPI backend and SQLite persistence.
- **Phase 8+**: Comprehensive product/documentation website on GitHub Pages and contributor ecosystem.

---

## License

This project is licensed under the [MIT License](LICENSE).
