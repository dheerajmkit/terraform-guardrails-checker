"""Plain-text findings report rendering."""

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def to_text(findings):
    """Render findings as plain text, worst severity first."""
    if not findings:
        return ("# Terraform guardrails report\n\n"
                "No findings — all checks passed.\n")
    ordered = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9),
                       f["file"], f["line"]))
    lines = ["# Terraform guardrails report", ""]
    for finding in ordered:
        lines.append(f"{finding['file']}:{finding['line']} "
                     f"[{finding['severity']}] {finding['rule_id']} "
                     f"{finding['resource']}: {finding['message']}")
    lines.append("")
    lines.append(f"{len(findings)} finding(s)")
    return "\n".join(lines) + "\n"
