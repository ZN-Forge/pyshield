"""Benign Python script with safe practices."""

import ast
import hashlib
import json
import os
import secrets
import subprocess

# Safe: environment lookups and placeholders
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD", "changeme")
API_KEY = os.environ.get("API_KEY")


def parse_safe_json(raw: str) -> dict:
    return json.loads(raw)


def parse_safe_literal(raw: str):
    return ast.literal_eval(raw)


def run_command_safely(args: list[str]) -> subprocess.CompletedProcess:
    # Safe: argument list, shell=False
    return subprocess.run(args, check=True, shell=False)


def run_default_safely(args: list[str]) -> subprocess.CompletedProcess:
    # Safe: default shell=False
    return subprocess.run(args, check=True)


def compute_secure_hash(data: bytes) -> str:
    # Safe: SHA-256
    return hashlib.sha256(data).hexdigest()


def compute_checksum(data: bytes) -> str:
    # Safe: md5 explicitly marked for non-security use
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def generate_secure_token() -> str:
    # Safe: standard secrets module
    return secrets.token_hex(32)


class SafeModel:
    def eval(self) -> None:
        """PyTorch-style eval mode."""
        pass

    def md5(self) -> str:
        """Custom method name."""
        return "custom"


def main() -> None:
    model = SafeModel()
    model.eval()
    token = generate_secure_token()
    print(f"Clean code executed safely: {token[:4]}")


if __name__ == "__main__":
    main()
