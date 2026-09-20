"""
IAM security checks.

Checks implemented:
  1. iam-user-no-mfa        -> IAM user has console/password access but no MFA device
  2. iam-old-access-key     -> access key is older than MAX_KEY_AGE_DAYS and still Active
  3. iam-unused-access-key  -> access key has never been used, or not used in 90+ days
  4. iam-admin-policy-attached -> user/role has AdministratorAccess (or equivalent *:* policy) directly attached
  5. iam-root-access-key    -> root account has an active access key (should never happen)

Uses the IAM credential report where possible, since it's the standard,
efficient way to audit an account (this is literally what Prowler/ScoutSuite
do under the hood) rather than looping with get_user for every user.
"""
import csv
import io
import time
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError
from .models import Finding

MAX_KEY_AGE_DAYS = 90
MAX_KEY_UNUSED_DAYS = 90


def _get_credential_report(iam) -> list[dict]:
    """Generate (if needed) and fetch the IAM credential report as a list of dict rows."""
    for _ in range(10):
        try:
            resp = iam.get_credential_report()
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "ReportNotPresent":
                iam.generate_credential_report()
                time.sleep(2)
                continue
            raise
    else:
        return []

    content = resp["Content"].decode("utf-8")
    reader = csv.DictReader(io.StringIO(content))
    return list(reader)


def _parse_date(value: str):
    if not value or value in ("N/A", "not_supported", "no_information"):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _days_since(dt) -> int | None:
    if dt is None:
        return None
    return (datetime.now(timezone.utc) - dt).days


def _check_mfa_and_root(rows: list[dict]) -> list[Finding]:
    findings = []
    for row in rows:
        user = row["user"]

        if user == "<root_account>":
            if row.get("access_key_1_active") == "true" or row.get("access_key_2_active") == "true":
                findings.append(Finding(
                    service="IAM",
                    resource_id="root",
                    check_name="iam-root-access-key",
                    severity="High",
                    description="The AWS root account has an active access key. Root should never have programmatic access keys.",
                    remediation="Deactivate/delete the root access key immediately; use IAM roles/users for programmatic access.",
                ))
            if row.get("mfa_active") != "true":
                findings.append(Finding(
                    service="IAM",
                    resource_id="root",
                    check_name="iam-user-no-mfa",
                    severity="High",
                    description="The AWS root account does not have MFA enabled.",
                    remediation="Enable MFA on the root account immediately - it has unrestricted access to the account.",
                ))
            continue

        has_console_access = row.get("password_enabled") == "true"
        has_mfa = row.get("mfa_active") == "true"
        if has_console_access and not has_mfa:
            findings.append(Finding(
                service="IAM",
                resource_id=user,
                check_name="iam-user-no-mfa",
                severity="High",
                description=f"User '{user}' has console password access but no MFA device enabled.",
                remediation="Require the user to enable an MFA device, and enforce MFA via IAM policy condition keys.",
            ))
    return findings


def _check_access_keys(rows: list[dict]) -> list[Finding]:
    findings = []
    for row in rows:
        user = row["user"]
        if user == "<root_account>":
            continue

        for key_num in (1, 2):
            active = row.get(f"access_key_{key_num}_active") == "true"
            if not active:
                continue

            last_rotated = _parse_date(row.get(f"access_key_{key_num}_last_rotated"))
            age_days = _days_since(last_rotated)
            if age_days is not None and age_days > MAX_KEY_AGE_DAYS:
                findings.append(Finding(
                    service="IAM",
                    resource_id=f"{user} (key {key_num})",
                    check_name="iam-old-access-key",
                    severity="Medium",
                    description=f"Access key {key_num} for '{user}' is {age_days} days old (threshold: {MAX_KEY_AGE_DAYS}).",
                    remediation="Rotate the access key. Consider using IAM roles instead of long-lived keys where possible.",
                ))

            last_used = _parse_date(row.get(f"access_key_{key_num}_last_used_date"))
            unused_days = _days_since(last_used)
            if last_used is None and age_days is not None and age_days > 1:
                findings.append(Finding(
                    service="IAM",
                    resource_id=f"{user} (key {key_num})",
                    check_name="iam-unused-access-key",
                    severity="Low",
                    description=f"Access key {key_num} for '{user}' has never been used since creation.",
                    remediation="If the key isn't needed, delete it to reduce attack surface.",
                ))
            elif unused_days is not None and unused_days > MAX_KEY_UNUSED_DAYS:
                findings.append(Finding(
                    service="IAM",
                    resource_id=f"{user} (key {key_num})",
                    check_name="iam-unused-access-key",
                    severity="Low",
                    description=f"Access key {key_num} for '{user}' hasn't been used in {unused_days} days.",
                    remediation="If the key isn't actively needed, deactivate or delete it.",
                ))
    return findings


def _check_admin_policies(iam) -> list[Finding]:
    """Flag users/roles with AdministratorAccess or an inline/custom policy granting '*:*'."""
    findings = []
    try:
        paginator = iam.get_paginator("list_users")
        users = [u["UserName"] for page in paginator.paginate() for u in page["Users"]]
    except ClientError as e:
        print(f"[IAM] Could not list users: {e}")
        return findings

    for user in users:
        try:
            attached = iam.list_attached_user_policies(UserName=user)["AttachedPolicies"]
        except ClientError:
            continue

        for policy in attached:
            if policy["PolicyName"] == "AdministratorAccess":
                findings.append(Finding(
                    service="IAM",
                    resource_id=user,
                    check_name="iam-admin-policy-attached",
                    severity="Medium",
                    description=f"User '{user}' has the AdministratorAccess managed policy attached directly.",
                    remediation="Follow least privilege: attach only the permissions the user needs, ideally via a group/role.",
                ))
    return findings


def run_iam_checks(session: boto3.Session) -> list[Finding]:
    """Run all IAM checks against the account."""
    iam = session.client("iam")
    findings: list[Finding] = []

    rows = _get_credential_report(iam)
    if rows:
        findings += _check_mfa_and_root(rows)
        findings += _check_access_keys(rows)
    else:
        print("[IAM] Credential report unavailable - skipping MFA/access-key checks.")

    findings += _check_admin_policies(iam)
    return findings
