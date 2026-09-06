"""Benign Python script with safe practices."""

import ast
import json
import subprocess


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


class SafeModel:
    def eval(self) -> None:
        """PyTorch-style eval mode."""
        pass


def main() -> None:
    model = SafeModel()
    model.eval()
    print("Clean code executed safely.")


if __name__ == "__main__":
    main()
