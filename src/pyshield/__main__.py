"""Main entrypoint for python -m pyshield."""

import sys

from pyshield.cli.main import app

if __name__ == "__main__":
    sys.exit(app())
