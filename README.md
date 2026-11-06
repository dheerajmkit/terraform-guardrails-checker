# terraform-guardrails-checker

Static security checks over Terraform files — no `terraform` binary
needed. It parses `.tf` files with a small built-in HCL-ish parser and
flags misconfigurations like security groups open to the internet,
unencrypted S3 buckets, and IAM policies with wildcard actions.

This is a **personal portfolio project** exploring cloud-security
automation and shift-left detection. It is a learning exercise, not a
production tool, and it has never been deployed at any employer.

## Quickstart

No dependencies to install — the standard library is all you need:

```bash
python3 run.py samples/
```

A finding looks like:

```
samples/vulnerable-sample.tf:14 [high] SG-001 aws_security_group.web: ingress open to the internet (ports 80-80)
```

The exit code is `1` when findings are present and `0` when the tree is
clean, so the checker can gate a commit or a CI step.

Machine-readable output and severity filtering:

```bash
python3 run.py --json samples/ > findings.json
python3 run.py --min-severity high samples/
```

Suppress a single finding with a comment on the block's line or the
line directly above it:

```hcl
# tfcheck:ignore=TAG-001
resource "aws_s3_bucket" "internal" {
  ...
}
```

## Checks

| ID | Title | Severity |
| -- | ----- | -------- |
| `SG-001` | Security group ingress open to `0.0.0.0/0` / `::/0` | high |
| `S3-001` | S3 bucket without server-side encryption | medium |
| `S3-002` | S3 bucket with a public canned ACL | high |
| `IAM-001` | IAM policy statement with wildcard action/resource | high |
| `RDS-001` | RDS instance without `storage_encrypted = true` | high |
| `EBS-001` | EBS volume without `encrypted = true` | medium |
| `TAG-001` | Taggable resource missing `Name`/`Environment` tags | low |

## Features

- **Built-in HCL-ish parser** — no `terraform` binary required; blocks,
  labels, attributes, lists, object literals, and heredocs.
- **Severity levels** — every finding carries a severity; filter with
  `--min-severity critical|high|medium|low`.
- **JSON output** (`--json`) for piping into other tools.
- **Suppression comments** (`# tfcheck:ignore=RULE-ID`) for accepted
  risks, scoped to a single block.

## Try it

```bash
python3 run.py samples/                          # text report
python3 run.py --json samples/                   # JSON report
python3 run.py --min-severity high samples/      # high and above only
python3 -m pytest tests/ -v                      # unit tests
```

See [docs/USAGE.md](docs/USAGE.md) for the check suite, suppression
format, and CI notes, and [examples/ci-step.yml](examples/ci-step.yml)
for a sample GitHub Actions step.

## Project layout

```
run.py                  # CLI: python3 run.py [--json] [--min-severity L] <path>
tfcheck/
  __init__.py
  parser.py             # HCL-ish tokenizer + block parser, heredoc support
  checks.py             # the check suite -> finding dicts
  engine.py             # file walk, check dispatch, suppression handling
  report.py             # plain-text and JSON report rendering
samples/
  vulnerable-sample.tf  # trips the day-1 checks (fictional resources)
  clean-sample.tf       # passes every check
  mixed-sample.tf       # RDS/EBS/ACL/tag issues + one suppressed finding
tests/                  # pytest unit tests
docs/USAGE.md           # full usage guide
examples/               # sample CI step
```
