"""Check engine: parse .tf files and run the check suite."""
import os

from .parser import parse_text, find_suppressions
from . import checks


def _suppressed(suppressions, line, rule_id):
    """A tfcheck:ignore comment on the block's line or the line above."""
    ignored = suppressions.get(line, set()) | suppressions.get(line - 1, set())
    return rule_id in ignored


def check_file(path):
    """Run every check against one .tf file; return a list of findings."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    blocks = parse_text(text, path)
    suppressions = find_suppressions(text)
    findings = []
    for check in checks.CHECKS:
        for finding in check["run"](blocks, path):
            if _suppressed(suppressions, finding["line"], finding["rule_id"]):
                continue
            findings.append(finding)
    return findings


def check_path(path):
    """Run every check against a .tf file or a directory of .tf files."""
    if os.path.isfile(path):
        return check_file(path)
    findings = []
    for dirpath, _dirnames, filenames in os.walk(path):
        for name in sorted(filenames):
            if name.endswith(".tf"):
                findings.extend(check_file(os.path.join(dirpath, name)))
    return findings
