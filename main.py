"""
Cloud Security Posture Scanner - main entry point.

Usage:
    python main.py                      # scans default profile, us-east-1
    python main.py --profile myprofile --region us-west-2
    python main.py --output findings.json

Requires an AWS credential profile (via `aws configure --profile <name>`
or environment variables) that has, at minimum, the IAMReadOnlyAccess and
SecurityAudit managed policies attached - no write permissions needed.
"""
import argparse
import json
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import NoCredentialsError, ClientError

from scanner.s3_checks import run_s3_checks
from scanner.ec2_checks import run_ec2_checks
from scanner.iam_checks import run_iam_checks

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def parse_args():
    parser = argparse.ArgumentParser(description="Scan an AWS account for common security misconfigurations.")
    parser.add_argument("--profile", default=None, help="AWS named profile to use (default: default profile / env vars)")
    parser.add_argument("--region", default="us-east-1", help="AWS region for regional checks like EC2 (default: us-east-1)")
    parser.add_argument("--output", default="findings.json", help="Path to write JSON findings (default: findings.json)")
    return parser.parse_args()


def run_all_checks(session: boto3.Session, region: str) -> list[dict]:
    all_findings = []

    print("[*] Running S3 checks...")
    s3_findings = run_s3_checks(session)
    print(f"    -> {len(s3_findings)} findings")
    all_findings += s3_findings

    print(f"[*] Running EC2 checks in {region}...")
    ec2_findings = run_ec2_checks(session, region=region)
    print(f"    -> {len(ec2_findings)} findings")
    all_findings += ec2_findings

    print("[*] Running IAM checks...")
    iam_findings = run_iam_checks(session)
    print(f"    -> {len(iam_findings)} findings")
    all_findings += iam_findings

    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return [f.to_dict() for f in all_findings]


def main():
    args = parse_args()

    try:
        session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
        session.client("sts").get_caller_identity()
    except NoCredentialsError:
        print("ERROR: No AWS credentials found. Run `aws configure --profile <name>` first.")
        sys.exit(1)
    except ClientError as e:
        print(f"ERROR: Could not authenticate to AWS: {e}")
        sys.exit(1)

    findings = run_all_checks(session, args.region)

    summary = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1

    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "region": args.region,
        "summary": summary,
        "total_findings": len(findings),
        "findings": findings,
    }

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[+] Scan complete: {len(findings)} findings "
          f"(High: {summary['High']}, Medium: {summary['Medium']}, Low: {summary['Low']})")
    print(f"[+] Report written to {args.output}")


if __name__ == "__main__":
    main()
