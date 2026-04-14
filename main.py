#!/usr/bin/env python3
"""
DockCheck — Static analysis tool for Docker images, Dockerfiles and Docker Compose files.
Entry point.

Author: Thomas Girboux
Year: 2026
TFE - EPHEC Haute École

Usage:
    python main.py image <image_name> [--output <path>] [--severity <level>]
    python main.py dockerfile <path> [--output <path>]
    python main.py compose <path> [--output <path>]
    python main.py all --image <image_name> --dockerfile <path> --compose <path> [--output <path>]
"""

import os
import sys

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cli.cli import CLI  # noqa: E402
from core.i18n import get_text  # noqa: E402


def main() -> int:
    """
    Main entry point for DockCheck.

    Returns:
        int: Exit code.
            0 — analysis completed, no issues found.
            1 — analysis completed, issues detected (useful for CI/CD pipelines).
            2 — critical error during analysis.
    """
    cli = CLI()

    try:
        exit_code = cli.run()
    except KeyboardInterrupt:
        print("\n[DockCheck] Analysis interrupted by user.", file=sys.stderr)
        exit_code = 2
    except Exception as e:
        print(f"\n[DockCheck] Unexpected error: {e}", file=sys.stderr)
        exit_code = 2

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
