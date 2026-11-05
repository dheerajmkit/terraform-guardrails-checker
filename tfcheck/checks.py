"""Security checks over parsed Terraform blocks.

Each check takes (blocks, path) and returns a list of finding dicts:

    {"rule_id", "severity", "resource", "file", "line", "message"}
"""
import json


def _resources(blocks, resource_type):
    return [b for b in blocks
            if b.type == "resource" and b.labels[:1] == [resource_type]]


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def check_open_security_group(blocks, path):
    """SG-001: ingress rules open to 0.0.0.0/0 (or ::/0)."""
    findings = []
    for sg in _resources(blocks, "aws_security_group"):
        for ingress in sg.nested("ingress"):
            cidrs = []
            for attr in ("cidr_blocks", "ipv6_cidr_blocks"):
                cidrs.extend(str(c) for c in _as_list(ingress.attrs.get(attr)))
            if "0.0.0.0/0" in cidrs or "::/0" in cidrs:
                from_port = ingress.attrs.get("from_port", "?")
                to_port = ingress.attrs.get("to_port", "?")
                findings.append({
                    "rule_id": "SG-001",
                    "severity": "high",
                    "resource": sg.name,
                    "file": path,
                    "line": ingress.line,
                    "message": "ingress open to the internet "
                               f"(ports {from_port}-{to_port})",
                })
    return findings


def check_s3_encryption(blocks, path):
    """S3-001: S3 bucket without server-side encryption configured."""
    findings = []
    for bucket in _resources(blocks, "aws_s3_bucket"):
        if not bucket.nested("server_side_encryption_configuration"):
            findings.append({
                "rule_id": "S3-001",
                "severity": "medium",
                "resource": bucket.name,
                "file": path,
                "line": bucket.line,
                "message": "S3 bucket has no "
                           "server_side_encryption_configuration block",
            })
    return findings


def _iam_statements(policy_text):
    try:
        doc = json.loads(policy_text)
    except (ValueError, TypeError, AttributeError):
        return []
    statements = doc.get("Statement", [])
    return statements if isinstance(statements, list) else [statements]


def check_iam_wildcards(blocks, path):
    """IAM-001: IAM policy statement with wildcard action or resource."""
    findings = []
    for policy in _resources(blocks, "aws_iam_policy"):
        raw = policy.attrs.get("policy")
        if not isinstance(raw, str):
            continue
        for statement in _iam_statements(raw):
            if not isinstance(statement, dict):
                continue
            actions = [str(a) for a in _as_list(statement.get("Action"))]
            resources = [str(r) for r in _as_list(statement.get("Resource"))]
            if "*" in actions or "*" in resources:
                findings.append({
                    "rule_id": "IAM-001",
                    "severity": "high",
                    "resource": policy.name,
                    "file": path,
                    "line": policy.line,
                    "message": "IAM policy allows wildcard action/resource",
                })
                break
    return findings


SEVERITIES = ("critical", "high", "medium", "low")

REQUIRED_TAGS = ("Name", "Environment")
TAGGABLE_TYPES = {"aws_security_group", "aws_s3_bucket", "aws_db_instance",
                  "aws_ebs_volume"}


def check_rds_encryption(blocks, path):
    """RDS-001: RDS instance without storage encryption enabled."""
    findings = []
    for db in _resources(blocks, "aws_db_instance"):
        if db.attrs.get("storage_encrypted") is not True:
            findings.append({
                "rule_id": "RDS-001",
                "severity": "high",
                "resource": db.name,
                "file": path,
                "line": db.line,
                "message": "RDS instance does not set storage_encrypted = true",
            })
    return findings


def check_ebs_encryption(blocks, path):
    """EBS-001: EBS volume without encryption enabled."""
    findings = []
    for volume in _resources(blocks, "aws_ebs_volume"):
        if volume.attrs.get("encrypted") is not True:
            findings.append({
                "rule_id": "EBS-001",
                "severity": "medium",
                "resource": volume.name,
                "file": path,
                "line": volume.line,
                "message": "EBS volume does not set encrypted = true",
            })
    return findings


def check_s3_public_acl(blocks, path):
    """S3-002: S3 bucket with a public canned ACL."""
    findings = []
    for bucket in _resources(blocks, "aws_s3_bucket"):
        acl = str(bucket.attrs.get("acl", "")).strip()
        if acl in ("public-read", "public-read-write"):
            findings.append({
                "rule_id": "S3-002",
                "severity": "high",
                "resource": bucket.name,
                "file": path,
                "line": bucket.line,
                "message": f"S3 bucket uses public ACL {acl!r}",
            })
    return findings


def _tags_of(block):
    tags = block.attrs.get("tags")
    if isinstance(tags, dict):
        return tags
    nested = block.nested("tags")
    if nested and isinstance(nested[0].attrs, dict):
        return nested[0].attrs
    return {}


def check_required_tags(blocks, path):
    """TAG-001: taggable resource missing Name/Environment tags."""
    findings = []
    for block in blocks:
        if block.type != "resource" or not block.labels:
            continue
        if block.labels[0] not in TAGGABLE_TYPES:
            continue
        tags = _tags_of(block)
        missing = [t for t in REQUIRED_TAGS if t not in tags]
        if missing:
            findings.append({
                "rule_id": "TAG-001",
                "severity": "low",
                "resource": block.name,
                "file": path,
                "line": block.line,
                "message": "missing required tags: " + ", ".join(missing),
            })
    return findings


CHECKS = [
    {"id": "SG-001",
     "title": "Security group ingress open to the internet",
     "severity": "high",
     "run": check_open_security_group},
    {"id": "S3-001",
     "title": "S3 bucket without server-side encryption",
     "severity": "medium",
     "run": check_s3_encryption},
    {"id": "IAM-001",
     "title": "IAM policy with wildcard action or resource",
     "severity": "high",
     "run": check_iam_wildcards},
    {"id": "RDS-001",
     "title": "RDS instance without storage encryption",
     "severity": "high",
     "run": check_rds_encryption},
    {"id": "EBS-001",
     "title": "EBS volume without encryption",
     "severity": "medium",
     "run": check_ebs_encryption},
    {"id": "S3-002",
     "title": "S3 bucket with public ACL",
     "severity": "high",
     "run": check_s3_public_acl},
    {"id": "TAG-001",
     "title": "Resource missing required tags (Name, Environment)",
     "severity": "low",
     "run": check_required_tags},
]
