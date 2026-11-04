"""terraform-guardrails-checker: static security checks for Terraform."""

from .engine import check_file, check_path
from .parser import parse_text, parse_file
from . import checks

__all__ = ["check_file", "check_path", "parse_text", "parse_file", "checks"]
__version__ = "0.1.0"
