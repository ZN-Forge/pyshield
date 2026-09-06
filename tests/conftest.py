"""Shared pytest fixtures and test helpers for PyShield."""

import ast
from pathlib import Path

import pytest

from pyshield.rules.base import ASTContext


def make_context(source: str, filename: str = "sample.py") -> ASTContext:
    """Helper to construct an ASTContext from a source string."""
    tree = ast.parse(source, filename=filename)
    return ASTContext.create(file_path=Path(filename), source_code=source, tree=tree)


@pytest.fixture
def parse_context():
    """Fixture providing helper function to make ASTContext."""
    return make_context
