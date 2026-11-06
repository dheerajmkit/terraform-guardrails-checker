# Usage guide

terraform-guardrails-checker is a personal portfolio project: static
security checks for Terraform files in pure Python 3 (standard library
only). It has never been deployed at any employer — it exists to
demonstrate cloud-security automation skills.

## Install

Nothing to install beyond Python 3. Clone the repo and run from its root:

```bash
git clone https://github.com/dheerajmkit/terraform-guardrails-checker.git
cd terraform-guardrails-checker
```

## Basic check

```bash
python3 run.py <file.tf or directory>
```

Exit code `1` means findings were reported; `0` means everything passed.

## JSON mode

For piping into other tools:

```bash
python3 run.py --json terraform/ > findings.json
```

Each finding has `rule_id`, `severity`, `resource`, `file`, `line`,
and `message`.

## Severity filtering

Only fail on what matters to you:

```bash
python3 run.py --min-severity high terraform/
```

Levels: `critical`, `high`, `medium`, `low` (default `low`).

## Suppression comments

Silence a single accepted risk with a comment on the block's line or
the line directly above it:

```hcl
# tfcheck:ignore=TAG-001
resource "aws_s3_bucket" "internal" {
  bucket = "example-internal-2026"
}
```

Multiple rules: `# tfcheck:ignore=SG-001,S3-002`. Suppressions are
per-block, never global.

## The check suite

| ID | Title | Severity |
| -- | ----- | -------- |
| `SG-001` | Security group ingress open to `0.0.0.0/0` / `::/0` | high |
| `S3-001` | S3 bucket without server-side encryption | medium |
| `S3-002` | S3 bucket with a public canned ACL | high |
| `IAM-001` | IAM policy statement with wildcard action/resource | high |
| `RDS-001` | RDS instance without `storage_encrypted = true` | high |
| `EBS-001` | EBS volume without `encrypted = true` | medium |
| `TAG-001` | Taggable resource missing `Name`/`Environment` tags | low |

## CI integration

See `examples/ci-step.yml` for a GitHub Actions step that fails the
build on high-or-worse findings.

## Parser scope

The built-in parser understands blocks, labels, attributes,
strings/numbers/booleans, lists, object literals, function calls (kept
opaque), and heredoc strings. It does not implement full HCL2 —
`dynamic` blocks, complex expressions, and `jsonencode()` policies are
parsed best-effort and skipped by checks when opaque.

## Tests

```bash
python3 -m pytest tests/ -v
```
