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

## Checks (day 1)

| ID | Title | Severity |
| -- | ----- | -------- |
| `SG-001` | Security group ingress open to `0.0.0.0/0` / `::/0` | high |
| `S3-001` | S3 bucket without server-side encryption | medium |
| `IAM-001` | IAM policy statement with wildcard action/resource | high |

## Project layout

```
run.py                  # CLI: python3 run.py <file-or-dir>
tfcheck/
  __init__.py
  parser.py             # HCL-ish tokenizer + block parser, heredoc support
  checks.py             # the check suite -> finding dicts
  engine.py             # file walk, check dispatch
  report.py             # plain-text report rendering
samples/
  vulnerable-sample.tf  # trips every check (fictional resources)
  clean-sample.tf       # passes every check
```

## Notes

- The parser is intentionally minimal: it understands blocks, labels,
  attributes, lists, object literals, and heredocs. Anything it does
  not understand is skipped, never fatal.
- IAM policy documents are parsed as JSON (heredoc style); policies
  built with `jsonencode()` are reported as unparseable and skipped.

## Roadmap

- **Day 2:** RDS/EBS encryption checks, public S3 ACLs, missing-tag
  checks, severity filtering, JSON output, and `tfcheck:ignore`
  suppression comments.
- **Day 3:** pytest unit tests, usage docs, and a sample CI step.
