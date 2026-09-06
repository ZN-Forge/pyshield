# PyShield

[![CI](https://github.com/ZN-Forge/pyshield/actions/workflows/ci.yml/badge.svg)](https://github.com/ZN-Forge/pyshield/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![Managed with uv](https://img.shields.io/badge/managed%20with-uv-blueviolet.svg)](https://docs.astral.sh/uv/)

**PyShield** is a developer-focused, open-source static security analysis platform for Python projects, maintained under the [**ZN-Forge**](https://github.com/ZN-Forge) organization.

Its primary purpose is to help developers identify potential security vulnerabilities in their code before reaching production through fast, deterministic AST analysis.

---

> [!NOTE]
> **Current Status: Phase 1 (Alpha / Early Foundation)**
> PyShield is currently in Phase 1 development. The core deterministic static analysis engine, rule registry, initial execution/injection rules, CLI, and terminal reporter are implemented and tested. Future capabilities (AI context, React UI, dependency scanning, etc.) are planned for later phases.

---

## Core Philosophy

1. **Deterministic-First**: Security detection is powered primarily by deterministic AST analysis and strict rules. Findings are verifiable and reproducible.
2. **Local-First & Privacy-Focused**: Source code is analyzed entirely on your local machine and is never transmitted to external services.
3. **Core Decoupling**: The static security analysis engine is strictly decoupled from presentation, web server, and persistence layers.
4. **Minimal Dependencies**: The core analysis leverages Python's built-in `ast` standard library to remain fast, lightweight, and maintainable.
5. **Zero False-Positive Focus**: Rules are designed conservatively to highlight high-confidence security hazards without flooding developers with noise.

---

## Supported Rules (Phase 1)

| Rule ID | Name | Severity | CWE | Description |
| :--- | :--- | :--- | :--- | :--- |
| **`PS101`** | Dangerous `eval()` usage | `CRITICAL` | CWE-95 | Detects calls to built-in `eval()`, preventing dynamic code execution risks. |
| **`PS102`** | Dangerous `exec()` usage | `CRITICAL` | CWE-95 | Detects calls to built-in `exec()`, preventing dynamic statement execution vulnerabilities. |
| **`PS103`** | Use of `os.system()` | `HIGH` | CWE-78 | Detects calls to `os.system()` which execute commands via shell strings. |
| **`PS104`** | Unsafe `subprocess` execution | `HIGH` | CWE-78 | Detects subprocess execution calls configured with `shell=True`. |

---

## Installation & Development Setup

PyShield uses [`uv`](https://docs.astral.sh/uv/) for reproducible, isolated project environment management.

### Prerequisites
- Python 3.11 or higher
- `uv` package manager

### Setup
Clone the repository and synchronize the isolated virtual environment:

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

## Planned Architecture (Future Phases)

The following capabilities are deliberately planned for subsequent phases:

- **Phase 2+**: Secret detection engine (`PS2xx`) and Cryptography rules (`PS3xx`).
- **Phase 3+**: Dependency vulnerability scanning (`PS8xx`) and Framework-specific rules (Django, FastAPI, Flask).
- **Phase 4+**: Standard SARIF, JSON, and Markdown export formats.
- **Phase 5+**: Optional Local AI analysis layer (via Ollama / llama.cpp) to explain and contextualize deterministic findings.
- **Phase 6+**: Local Web UI (React + TypeScript + Vite + Tailwind CSS) with FastAPI backend and SQLite persistence.
- **Phase 7+**: PyPI distribution package and comprehensive documentation website on GitHub Pages.

---

## License

This project is licensed under the [MIT License](LICENSE).
