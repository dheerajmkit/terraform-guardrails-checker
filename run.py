#!/usr/bin/env python3
"""CLI entry point: static security checks over Terraform files.

Usage:
    python3 run.py [--json] [--min-severity LEVEL] <path-to-.tf-file-or-directory>

Exits 1 when findings are present, 0 when the tree is clean.
"""
import sys

from tfcheck.checks import SEVERITIES
from tfcheck.engine import check_path
from tfcheck.report import to_text, to_json, SEVERITY_ORDER


def _filter_severity(findings, minimum):
    threshold = SEVERITY_ORDER[minimum]
    return [f for f in findings
            if SEVERITY_ORDER.get(f["severity"], 99) <= threshold]


def main(argv):
    flags = []
    args = []
    i = 1
    min_severity = "low"
    while i < len(argv):
        token = argv[i]
        if token == "--json":
            flags.append(token)
        elif token == "--min-severity" and i + 1 < len(argv):
            min_severity = argv[i + 1].lower()
            i += 1
        elif token.startswith("-"):
            print(f"unknown flag: {token}", file=sys.stderr)
            return 2
        else:
            args.append(token)
        i += 1
    if len(args) != 1 or min_severity not in SEVERITIES:
        print("usage: python3 run.py [--json] [--min-severity LEVEL] <path>",
              file=sys.stderr)
        print(f"levels: {', '.join(SEVERITIES)}", file=sys.stderr)
        return 2
    findings = _filter_severity(check_path(args[0]), min_severity)
    if "--json" in flags:
        print(to_json(findings), end="")
    else:
        print(to_text(findings), end="")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
