# Mixed sample: several issues plus one suppressed finding.
# All names and IDs are fictional.

resource "aws_db_instance" "app" {
  identifier          = "example-app-db"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  allocated_storage   = 50
  storage_encrypted   = false
  skip_final_snapshot = true

  tags = {
    Name        = "app-db"
    Environment = "dev"
  }
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  # encrypted is not set -> defaults to false

  tags = {
    Name        = "app-data"
    Environment = "dev"
  }
}

resource "aws_s3_bucket" "public_assets" {
  bucket = "example-public-assets-2026"
  acl    = "public-read"

  tags = {
    Name        = "public-assets"
    Environment = "dev"
  }
}

# tfcheck:ignore=TAG-001
resource "aws_s3_bucket" "internal" {
  bucket = "example-internal-2026"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = {
    Name = "internal"
  }
}
