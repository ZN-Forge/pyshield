"""Development helper script to run all PyShield quality gates."""

import subprocess
import sys


def run(cmd: list[str]) -> None:
    print(f"\n==> Running: {' '.join(cmd)}")
    res = subprocess.run(cmd)
    if res.returncode != 0:
        print(f"FAILED: {' '.join(cmd)}")
        sys.exit(res.returncode)


def main() -> None:
    run(["uv", "run", "ruff", "check", "."])
    run(["uv", "run", "ruff", "format", "--check", "."])
    run(["uv", "run", "mypy", "src"])
    run(["uv", "run", "pytest", "--cov=pyshield", "--cov-report=term-missing"])
    print("\n[SUCCESS] All quality gates passed!")


if __name__ == "__main__":
    main()
