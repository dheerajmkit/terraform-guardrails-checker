# Intentionally insecure sample: every resource here trips a check.
# All names, IDs and addresses are fictional.

variable "vpc_id" {
  type    = string
  default = "vpc-0f1e2d3c4b5a69788"
}

resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Web tier security group"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "web-sg"
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "example-app-logs-2026"
  acl    = "private"

  tags = {
    Name = "app-logs"
  }
}

resource "aws_iam_policy" "deployer" {
  name        = "deployer-policy"
  description = "Overly broad deployer policy"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF
}
