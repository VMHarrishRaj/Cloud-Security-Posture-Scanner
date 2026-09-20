"""
Shared data model for scan findings.

Every check function returns a list of Finding objects. Keeping this
structure consistent is what lets main.py aggregate results from totally
different AWS services (S3, EC2, IAM) into one report/dashboard.
"""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone


@dataclass
class Finding:
    service: str          # e.g. "S3", "EC2", "IAM"
    resource_id: str      # bucket name, security group id, IAM user name, etc.
    check_name: str       # short machine-friendly name, e.g. "s3-public-bucket-policy"
    severity: str         # "High" | "Medium" | "Low"
    description: str      # what's wrong, in plain English
    remediation: str      # how to fix it
    region: str = "global"

    def to_dict(self) -> dict:
        return asdict(self)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
