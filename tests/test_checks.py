"""Unit tests for the Terraform guardrails checker.

Run with:  python3 -m pytest tests/ -v   (from the repo root)
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tfcheck.parser import parse_text, find_suppressions
from tfcheck.checks import CHECKS
from tfcheck.engine import check_file, check_path
from tfcheck.report import to_text, to_json

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def _sample(name):
    return os.path.join(SAMPLES, name)


def _run_all(text, path="test.tf"):
    from tfcheck.parser import parse_text as parse
    blocks = parse(text, path)
    findings = []
    for check in CHECKS:
        findings.extend(check["run"](blocks, path))
    return findings


def _ids(findings):
    return sorted(f["rule_id"] for f in findings)


def test_parser_reads_resource_blocks():
    blocks = parse_text('resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n')
    assert len(blocks) == 1
    assert blocks[0].name == "aws_s3_bucket.b"
    assert blocks[0].attrs["bucket"] == "x"


def test_parser_nested_blocks():
    text = ('resource "aws_security_group" "sg" {\n'
            '  ingress {\n    from_port = 80\n  }\n'
            '  ingress {\n    from_port = 443\n  }\n}\n')
    blocks = parse_text(text)
    assert len(blocks[0].nested("ingress")) == 2
    assert blocks[0].nested("ingress")[0].attrs["from_port"] == 80


def test_parser_lists_and_objects():
    text = ('resource "aws_security_group" "sg" {\n'
            '  ingress {\n    cidr_blocks = ["0.0.0.0/0", "10.0.0.0/8"]\n  }\n'
            '  tags = {\n    Name = "sg"\n  }\n}\n')
    blocks = parse_text(text)
    ingress = blocks[0].nested("ingress")[0]
    assert ingress.attrs["cidr_blocks"] == ["0.0.0.0/0", "10.0.0.0/8"]
    assert blocks[0].attrs["tags"] == {"Name": "sg"}


def test_parser_heredoc():
    text = ('resource "aws_iam_policy" "p" {\n'
            '  policy = <<EOF\n{"Statement": []}\nEOF\n}\n')
    blocks = parse_text(text)
    assert json.loads(blocks[0].attrs["policy"]) == {"Statement": []}


def test_parser_skips_comments():
    text = ('# a comment\nresource "aws_s3_bucket" "b" { # trailing\n'
            '  // another\n  bucket = "x" /* inline */\n}\n')
    blocks = parse_text(text)
    assert blocks[0].attrs["bucket"] == "x"


def test_open_security_group():
    text = ('resource "aws_security_group" "web" {\n'
            '  ingress {\n    from_port = 22\n    to_port = 22\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
    findings = _run_all(text)
    assert "SG-001" in _ids(findings)


def test_restricted_security_group_passes():
    text = ('resource "aws_security_group" "web" {\n'
            '  ingress {\n    from_port = 443\n    to_port = 443\n'
            '    cidr_blocks = ["203.0.113.0/24"]\n  }\n}\n')
    findings = _run_all(text)
    assert "SG-001" not in _ids(findings)


def test_egress_open_does_not_flag():
    text = ('resource "aws_security_group" "web" {\n'
            '  egress {\n    from_port = 0\n    to_port = 0\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
    findings = _run_all(text)
    assert "SG-001" not in _ids(findings)


def test_unencrypted_s3():
    text = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'
    assert "S3-001" in _ids(_run_all(text))


def test_encrypted_s3_passes():
    text = ('resource "aws_s3_bucket" "b" {\n'
            '  server_side_encryption_configuration {\n'
            '    rule {\n    }\n  }\n}\n')
    assert "S3-001" not in _ids(_run_all(text))


def test_iam_wildcard_action():
    text = ('resource "aws_iam_policy" "p" {\n'
            '  policy = <<EOF\n'
            '{"Statement": [{"Effect": "Allow", "Action": "*", '
            '"Resource": "arn:aws:s3:::x"}]}\nEOF\n}\n')
    assert "IAM-001" in _ids(_run_all(text))


def test_iam_scoped_policy_passes():
    text = ('resource "aws_iam_policy" "p" {\n'
            '  policy = <<EOF\n'
            '{"Statement": [{"Effect": "Allow", '
            '"Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::x"]}]}\n'
            'EOF\n}\n')
    assert "IAM-001" not in _ids(_run_all(text))


def test_rds_ebs_encryption():
    text = ('resource "aws_db_instance" "db" {\n'
            '  storage_encrypted = false\n}\n'
            'resource "aws_ebs_volume" "v" {\n}\n')
    ids = _ids(_run_all(text))
    assert "RDS-001" in ids
    assert "EBS-001" in ids


def test_public_acl():
    text = 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n'
    assert "S3-002" in _ids(_run_all(text))


def test_missing_tags():
    text = ('resource "aws_s3_bucket" "b" {\n'
            '  tags = {\n    Name = "b"\n  }\n}\n')
    assert "TAG-001" in _ids(_run_all(text))


def test_suppression_comment_parsed():
    text = ("# tfcheck:ignore=TAG-001\n"
            'resource "aws_s3_bucket" "b" {\n}\n')
    assert find_suppressions(text) == {1: {"TAG-001"}}


def test_vulnerable_sample_findings():
    findings = check_file(_sample("vulnerable-sample.tf"))
    ids = _ids(findings)
    assert ids.count("SG-001") == 2
    assert "S3-001" in ids and "IAM-001" in ids


def test_clean_sample_passes():
    assert check_file(_sample("clean-sample.tf")) == []


def test_suppressed_finding_skipped():
    findings = check_file(_sample("mixed-sample.tf"))
    internal = [f for f in findings
                if f["resource"] == "aws_s3_bucket.internal"]
    assert all(f["rule_id"] != "TAG-001" for f in internal)


def test_check_path_walks_directory():
    findings = check_path(SAMPLES)
    assert findings, "expected findings across the samples directory"


def test_report_text_and_json():
    findings = check_file(_sample("vulnerable-sample.tf"))
    text = to_text(findings)
    assert "# Terraform guardrails report" in text
    assert "SG-001" in text
    data = json.loads(to_json(findings))
    assert isinstance(data, list) and data[0]["rule_id"]
    assert to_text([]).strip().endswith("all checks passed.")
