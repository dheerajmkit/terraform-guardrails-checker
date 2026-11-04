#!/usr/bin/env python3
"""CLI entry point: static security checks over Terraform files.

Usage:
    python3 run.py <path-to-.tf-file-or-directory>

Exits 1 when findings are present, 0 when the tree is clean.
"""
import sys

from tfcheck.engine import check_path
from tfcheck.report import to_text


def main(argv):
    if len(argv) != 2:
        print("usage: python3 run.py <path>", file=sys.stderr)
        return 2
    findings = check_path(argv[1])
    print(to_text(findings), end="")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
