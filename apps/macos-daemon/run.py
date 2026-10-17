#!/usr/bin/env python3
"""Run TrustLine from its checkout without installing a Python package."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from trustline.__main__ import main

if __name__ == "__main__":
    main()
