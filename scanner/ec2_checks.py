"""
EC2 security group checks.

Checks implemented:
  1. ec2-open-ssh      -> security group allows 0.0.0.0/0 (or ::/0) on port 22
  2. ec2-open-rdp      -> security group allows 0.0.0.0/0 (or ::/0) on port 3389
  3. ec2-open-all-ports -> security group allows 0.0.0.0/0 on ALL ports/protocols
  4. ec2-unattached-eip -> Elastic IP allocated but not attached to any instance (cost + minor risk)
"""
import boto3
from botocore.exceptions import ClientError
from .models import Finding

SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
}

PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}


def _is_public_range(ip_ranges, ipv6_ranges) -> bool:
    for r in ip_ranges:
        if r.get("CidrIp") in PUBLIC_CIDRS:
            return True
    for r in ipv6_ranges:
        if r.get("CidrIpv6") in PUBLIC_CIDRS:
            return True
    return False


def _check_security_groups(ec2) -> list[Finding]:
    findings = []
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        groups = []
        for page in paginator.paginate():
            groups.extend(page["SecurityGroups"])
    except ClientError as e:
        print(f"[EC2] Could not describe security groups: {e}")
        return findings

    for sg in groups:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", sg_id)

        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            ip_protocol = perm.get("IpProtocol")
            is_public = _is_public_range(perm.get("IpRanges", []), perm.get("Ipv6Ranges", []))

            if not is_public:
                continue

            if ip_protocol == "-1":
                findings.append(Finding(
                    service="EC2",
                    resource_id=f"{sg_id} ({sg_name})",
                    check_name="ec2-open-all-ports",
                    severity="High",
                    description="Security group allows ALL traffic (all ports/protocols) from the public internet.",
                    remediation="Restrict the rule to specific ports and trusted CIDR ranges.",
                ))
                continue

            if from_port is None:
                continue

            for port, label in SENSITIVE_PORTS.items():
                if from_port <= port <= (to_port or from_port):
                    findings.append(Finding(
                        service="EC2",
                        resource_id=f"{sg_id} ({sg_name})",
                        check_name=f"ec2-open-{label.lower()}",
                        severity="High",
                        description=f"Security group allows {label} (port {port}) from the public internet (0.0.0.0/0).",
                        remediation=f"Restrict port {port} to a specific trusted IP range or use a bastion/SSM Session Manager instead.",
                    ))

    return findings


def _check_unattached_eips(ec2) -> list[Finding]:
    findings = []
    try:
        addresses = ec2.describe_addresses().get("Addresses", [])
    except ClientError as e:
        print(f"[EC2] Could not describe addresses: {e}")
        return findings

    for addr in addresses:
        if "InstanceId" not in addr and "NetworkInterfaceId" not in addr:
            findings.append(Finding(
                service="EC2",
                resource_id=addr.get("PublicIp", addr.get("AllocationId", "unknown")),
                check_name="ec2-unattached-eip",
                severity="Low",
                description="Elastic IP is allocated but not attached to any running instance or ENI.",
                remediation="Release the Elastic IP if it's unused to avoid unnecessary attack surface and cost.",
            ))
    return findings


def run_ec2_checks(session: boto3.Session, region: str = "us-east-1") -> list[Finding]:
    """Run all EC2 checks in a given region."""
    ec2 = session.client("ec2", region_name=region)
    findings: list[Finding] = []
    findings += _check_security_groups(ec2)
    findings += _check_unattached_eips(ec2)

    for f in findings:
        f.region = region
    return findings
