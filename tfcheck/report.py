"""Plain-text and JSON findings report rendering."""
import json

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _ordered(findings):
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9),
                       f["file"], f["line"]))


def to_text(findings):
    """Render findings as plain text, worst severity first."""
    if not findings:
        return ("# Terraform guardrails report\n\n"
                "No findings — all checks passed.\n")
    lines = ["# Terraform guardrails report", ""]
    for finding in _ordered(findings):
        lines.append(f"{finding['file']}:{finding['line']} "
                     f"[{finding['severity']}] {finding['rule_id']} "
                     f"{finding['resource']}: {finding['message']}")
    lines.append("")
    lines.append(f"{len(findings)} finding(s)")
    return "\n".join(lines) + "\n"


def to_json(findings):
    """Render findings as a JSON list, worst severity first."""
    return json.dumps([
        {"rule_id": f["rule_id"], "severity": f["severity"],
         "resource": f["resource"], "file": f["file"], "line": f["line"],
         "message": f["message"]}
        for f in _ordered(findings)
    ], indent=2) + "\n"
