# Clean sample: every resource here passes the checks.
# All names, IDs and addresses are fictional (203.0.113.0/24 is TEST-NET-3).

variable "vpc_id" {
  type    = string
  default = "vpc-0f1e2d3c4b5a69788"
}

resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = var.vpc_id

  ingress {
    description = "HTTP from the office range"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "web-sg"
    Environment = "prod"
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "example-app-logs-2026"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = {
    Name        = "app-logs"
    Environment = "prod"
  }
}

resource "aws_iam_policy" "reader" {
  name = "reader-policy"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::example-app-logs-2026",
        "arn:aws:s3:::example-app-logs-2026/*"
      ]
    }
  ]
}
EOF
}
