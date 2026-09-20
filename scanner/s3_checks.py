"""
S3 bucket security checks.

Checks implemented:
  1. s3-public-acl           -> bucket ACL grants access to AllUsers / AuthenticatedUsers
  2. s3-public-bucket-policy -> bucket policy has a Statement that allows Principal "*"
  3. s3-block-public-access-off -> account/bucket-level "Block Public Access" not fully enabled
  4. s3-no-encryption        -> bucket has no default server-side encryption configured
  5. s3-no-versioning        -> bucket does not have versioning enabled (ransomware/accidental delete risk)
"""
import json
import boto3
from botocore.exceptions import ClientError
from .models import Finding

PUBLIC_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def _check_public_acl(s3, bucket_name: str) -> list[Finding]:
    findings = []
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
    except ClientError:
        return findings

    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {})
        uri = grantee.get("URI")
        if uri in PUBLIC_URIS:
            permission = grant.get("Permission")
            findings.append(Finding(
                service="S3",
                resource_id=bucket_name,
                check_name="s3-public-acl",
                severity="High",
                description=(
                    f"Bucket ACL grants '{permission}' to "
                    f"{'all authenticated AWS users' if 'AuthenticatedUsers' in uri else 'everyone on the internet'}."
                ),
                remediation=(
                    "Remove the public grant from the bucket ACL "
                    "(aws s3api put-bucket-acl) and enable S3 Block Public Access."
                ),
            ))
    return findings


def _check_public_bucket_policy(s3, bucket_name: str) -> list[Finding]:
    findings = []
    try:
        policy_resp = s3.get_bucket_policy(Bucket=bucket_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return findings
        return findings

    try:
        policy = json.loads(policy_resp["Policy"])
    except (KeyError, json.JSONDecodeError):
        return findings

    for statement in policy.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        is_public = principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*")
        if is_public:
            findings.append(Finding(
                service="S3",
                resource_id=bucket_name,
                check_name="s3-public-bucket-policy",
                severity="High",
                description="Bucket policy contains an Allow statement with Principal '*' (public access).",
                remediation="Scope the Principal to specific accounts/roles, or remove the statement entirely.",
            ))
            break
    return findings


def _check_block_public_access(s3, bucket_name: str) -> list[Finding]:
    findings = []
    try:
        resp = s3.get_public_access_block(Bucket=bucket_name)
        config = resp["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            findings.append(Finding(
                service="S3",
                resource_id=bucket_name,
                check_name="s3-block-public-access-off",
                severity="High",
                description="No S3 Block Public Access configuration exists on this bucket.",
                remediation="Enable all four Block Public Access settings at the bucket or account level.",
            ))
        return findings

    if not all([
        config.get("BlockPublicAcls"),
        config.get("IgnorePublicAcls"),
        config.get("BlockPublicPolicy"),
        config.get("RestrictPublicBuckets"),
    ]):
        findings.append(Finding(
            service="S3",
            resource_id=bucket_name,
            check_name="s3-block-public-access-off",
            severity="Medium",
            description="One or more S3 Block Public Access settings are disabled for this bucket.",
            remediation="Set BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy and RestrictPublicBuckets all to true.",
        ))
    return findings


def _check_encryption(s3, bucket_name: str) -> list[Finding]:
    findings = []
    try:
        s3.get_bucket_encryption(Bucket=bucket_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            findings.append(Finding(
                service="S3",
                resource_id=bucket_name,
                check_name="s3-no-encryption",
                severity="Medium",
                description="Bucket has no default server-side encryption configured.",
                remediation="Enable default encryption (SSE-S3 or SSE-KMS) on the bucket.",
            ))
    return findings


def _check_versioning(s3, bucket_name: str) -> list[Finding]:
    findings = []
    resp = s3.get_bucket_versioning(Bucket=bucket_name)
    if resp.get("Status") != "Enabled":
        findings.append(Finding(
            service="S3",
            resource_id=bucket_name,
            check_name="s3-no-versioning",
            severity="Low",
            description="Bucket versioning is not enabled, increasing risk from accidental deletes or ransomware.",
            remediation="Enable versioning: aws s3api put-bucket-versioning --bucket <name> --versioning-configuration Status=Enabled",
        ))
    return findings


def run_s3_checks(session: boto3.Session) -> list[Finding]:
    """Run all S3 checks against every bucket in the account."""
    s3 = session.client("s3")
    findings: list[Finding] = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        print(f"[S3] Could not list buckets: {e}")
        return findings

    for bucket in buckets:
        name = bucket["Name"]
        findings += _check_public_acl(s3, name)
        findings += _check_public_bucket_policy(s3, name)
        findings += _check_block_public_access(s3, name)
        findings += _check_encryption(s3, name)
        findings += _check_versioning(s3, name)

    return findings
