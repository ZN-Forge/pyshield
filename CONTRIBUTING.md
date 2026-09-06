# Contributing to PyShield

Thank you for your interest in contributing to PyShield!

PyShield is an open-source security analysis platform maintained under the **ZN-Forge** organization. We welcome contributions from developers of all backgrounds.

## Development Principles

1. **Deterministic-first**: Security rules must be deterministic, accurate, and have minimal false positives.
2. **Local-first & Privacy-conscious**: Source code must never leave the local environment by default.
3. **Core Decoupling**: Core analysis must remain completely decoupled from presentation, API, and database layers.
4. **Minimal Dependencies**: Do not add dependencies unless strictly required.
5. **Rigorous Quality**: Every new feature or rule must include unit tests, type annotations, and pass all quality gates.

## Development Setup

We use [`uv`](https://docs.astral.sh/uv/) for project and dependency management.

### 1. Clone the repository
```bash
git clone https://github.com/ZN-Forge/pyshield.git
cd pyshield
```

### 2. Set up isolated environment
```bash
uv sync
```

This creates a local `.venv/` and installs all runtime and development dependencies locked in `uv.lock`.

### 3. Run Quality Gates
Before submitting a PR, make sure all quality checks pass:

```bash
# Run tests with coverage
uv run pytest --cov=pyshield --cov-report=term-missing

# Run linter
uv run ruff check .

# Run code formatter check
uv run ruff format --check .

# Run type checker
uv run mypy src
```

## Adding a Security Rule

When contributing a new rule:
1. Choose an appropriate ID (e.g., `PS1xx` for Execution/Injection).
2. Implement the rule in `src/pyshield/rules/builtin/` inheriting from `BaseRule`.
3. Provide comprehensive positive tests (detect vulnerable pattern), negative tests (safe patterns), and edge cases (avoiding false positives).
4. Register the rule in `src/pyshield/core/registry.py`.
5. Update documentation and rule references.
