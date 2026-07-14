#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   AWS Control Tower — Member Account Pre-Enrollment Readiness Tool           ║
║   Version: 3.0  |  Run this INSIDE the member account (CloudShell)           ║
║                                                                              ║
║   PURPOSE: Self-assessment of a single account BEFORE it is enrolled         ║
║   into Control Tower. No management account access required.                 ║
║                                                                              ║
║   USAGE:                                                                     ║
║     python3 <filename.py>                                                    ║
║     python3 <filename.py> --region eu-west-1                                 ║
║     python3 <filename.py> --regions us-east-1 eu-west-1 ap-east-1            ║
║                                                                              ║
║   OUTPUTS:                                                                   ║
║     Console  : colour-coded live results                                     ║
║     .txt file: plain-text report (email / support ticket)                    ║
║     .html file: rich browser report for customer handover                    ║
║                                                                              ║
║   PERMISSIONS NEEDED (in this member account):                               ║
║     iam:GetAccountSummary, iam:GetRole, iam:ListRoles                        ║
║     iam:GetAccountPasswordPolicy, iam:ListPolicies                           ║
║     iam:ListUsers, iam:ListAccessKeys                                        ║
║     config:DescribeConfigurationRecorders                                    ║
║     config:DescribeDeliveryChannels                                          ║
║     config:DescribeConfigRules                                               ║
║     config:GetDiscoveredResourceCounts                                       ║
║     cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus                     ║
║     cloudtrail:GetEventSelectors                                             ║
║     ec2:DescribeRegions, ec2:DescribeReservedInstances                       ║
║     ec2:DescribeVpcs, ec2:DescribeSecurityGroups                             ║
║     ec2:GetEbsEncryptionByDefault                                            ║
║     s3:ListAllMyBuckets                                                      ║
║     s3control:GetPublicAccessBlock                                           ║
║     guardduty:ListDetectors, guardduty:GetDetector                           ║
║     guardduty:GetAdministratorAccount                                        ║
║     securityhub:DescribeHub, securityhub:GetAdministratorAccount             ║
║     securityhub:GetEnabledStandards                                          ║
║     sns:ListTopics                                                           ║
║     lambda:ListFunctions                                                     ║
║     logs:DescribeLogGroups                                                   ║
║     kms:GetKeyPolicy                                                         ║
║     organizations:DescribeAccount (may be denied — handled gracefully)       ║
║     sts:GetCallerIdentity                                                    ║
║     support:DescribeSeverityLevels                                           ║
║     cloudformation:ListStacks                                                ║
║     savingsplans:DescribeSavingsPlans                                        ║
║     account:ListRegions, account:GetContactInformation                       ║
║     service-quotas:GetServiceQuota, service-quotas:GetAWSDefaultServiceQuota ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import boto3
import botocore
import json
import sys
import os
import re
import argparse
import textwrap
import datetime
import traceback
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Colour helpers
# ─────────────────────────────────────────────────────────────────────────────
class C:
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def strip_ansi(text: str) -> str:
    return re.sub(r'\033\[[0-9;]*m', '', text)

# ─────────────────────────────────────────────────────────────────────────────
# Status constants
# ─────────────────────────────────────────────────────────────────────────────
PASS  = "PASS"
FAIL  = "FAIL"
WARN  = "WARN"
INFO  = "INFO"
SKIP  = "SKIP"
MANUAL= "MANUAL"   # cannot be automated — requires human eye

CT_EXISTING_CONFIG_DOC = (
    "https://docs.aws.amazon.com/controltower/latest/userguide/"
    "existing-config-resources.html"
)
CT_BASELINE_CONFIG_RECORDER = "aws-controltower-BaselineConfigRecorder"
CT_BASELINE_CONFIG_DELIVERY_CHANNEL = "aws-controltower-BaselineConfigDeliveryChannel"

def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)

def utc_now_str() -> str:
    return utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")

def utc_stamp() -> str:
    return utc_now().strftime("%Y%m%d_%H%M%S")

STATUS_COLOUR = {
    PASS:   C.GREEN,
    FAIL:   C.RED,
    WARN:   C.YELLOW,
    INFO:   C.CYAN,
    SKIP:   C.DIM,
    MANUAL: C.MAGENTA,
}
STATUS_ICON = {
    PASS:   "✔",
    FAIL:   "✘",
    WARN:   "⚠",
    INFO:   "ℹ",
    SKIP:   "─",
    MANUAL: "✋",
}
STATUS_HTML_BG = {
    PASS:   "#f0fff4",
    FAIL:   "#fff5f5",
    WARN:   "#fffdf0",
    INFO:   "#f0fbff",
    SKIP:   "#f8f9fa",
    MANUAL: "#fdf0ff",
}
STATUS_HTML_BADGE = {
    PASS:   "#28a745",
    FAIL:   "#dc3545",
    WARN:   "#e6a817",
    INFO:   "#17a2b8",
    SKIP:   "#6c757d",
    MANUAL: "#8b5cf6",
}

TIMESTAMP = utc_stamp()

# ─────────────────────────────────────────────────────────────────────────────
# Result store
# ─────────────────────────────────────────────────────────────────────────────
RESULTS: list[dict] = []

def record(category: str, check: str, status: str,
           detail: str, action: str = "", region: str = "global"):
    RESULTS.append({
        "category": category,
        "check":    check,
        "status":   status,
        "detail":   detail,
        "action":   action,
        "region":   region,
    })

def emit(check: str, status: str, detail: str = ""):
    col  = STATUS_COLOUR.get(status, C.RESET)
    icon = STATUS_ICON.get(status, "?")
    print(f"    {col}{icon}  {check}{C.RESET}")
    if detail:
        for line in detail.splitlines():
            if line.strip():
                print(f"       {C.DIM}{line}{C.RESET}")

def section(num: str, title: str):
    bar = "─" * 72
    print(f"\n{C.BOLD}{C.BLUE}{bar}")
    print(f"  {num}  {title}")
    print(f"{bar}{C.RESET}")

def subsection(title: str):
    print(f"\n  {C.BOLD}{C.CYAN}▶ {title}{C.RESET}")

# ─────────────────────────────────────────────────────────────────────────────
# Safe API wrapper
# ─────────────────────────────────────────────────────────────────────────────
def api(func, **kwargs):
    """Returns (response_or_None, error_string_or_None)."""
    try:
        return func(**kwargs), None
    except botocore.exceptions.ClientError as e:
        return None, str(e)
    except Exception as e:
        return None, str(e)

# ═════════════════════════════════════════════════════════════════════════════
# CHECK FUNCTIONS
# Each function: runs the check, calls record(), calls emit(), returns nothing.
# ═════════════════════════════════════════════════════════════════════════════

# ─── SECTION 1: ACCOUNT IDENTITY ─────────────────────────────────────────────

def chk_identity(sts_client) -> dict:
    """Return identity dict for use by subsequent checks."""
    resp, err = api(sts_client.get_caller_identity)
    if err:
        record("Identity", "Caller Identity", FAIL,
               f"Cannot determine account identity: {err}",
               "Ensure CloudShell has valid credentials.")
        emit("Caller Identity", FAIL, err)
        return {}
    acct = resp["Account"]
    arn  = resp["Arn"]
    record("Identity", "Caller Identity", INFO,
           f"Account ID : {acct}\nCaller ARN : {arn}")
    emit("Caller Identity", INFO, f"Account: {acct}  |  Caller: {arn}")
    return resp

def chk_account_in_org(org_client, account_id: str):
    """Try Organizations:DescribeAccount — may be denied if not delegated."""
    resp, err = api(org_client.describe_account, AccountId=account_id)
    if err:
        if "AccessDenied" in str(err) or "AWSOrganizationsNotInUseException" in str(err):
            record("Organization", "Account: Org Membership",
                   WARN,
                   "Cannot read Organizations API from member account — this is normal.\n"
                   "The management account operator must verify this account is in the correct Org.",
                   "Ask the management account admin to confirm:\n"
                   "  aws organizations describe-account --account-id " + account_id)
            emit("Account: Org Membership", WARN,
                 "Organizations API not accessible from member (expected). Management account must verify.")
        else:
            record("Organization", "Account: Org Membership", FAIL,
                   f"Unexpected error: {err}")
            emit("Account: Org Membership", FAIL, err)
        return

    status = resp["Account"].get("Status", "UNKNOWN")
    name   = resp["Account"].get("Name", "?")
    if status == "ACTIVE":
        record("Organization", "Account: Org Membership", PASS,
               f"Account Name: {name}  |  Status: ACTIVE")
        emit("Account: Org Membership", PASS, f"Name: {name} | Status: ACTIVE")
    else:
        record("Organization", "Account: Org Membership", FAIL,
               f"Account Status: {status}  — must be ACTIVE for enrollment.",
               "Resolve billing/suspension issues before proceeding.")
        emit("Account: Org Membership", FAIL, f"Status={status} — must be ACTIVE")


# ─── SECTION 2: IAM CHECKS ───────────────────────────────────────────────────

def chk_ct_execution_role(iam_client):
    """
    AWSControlTowerExecution role trust policy logic:
    - Role absent          → PASS  (CT will create it)
    - Role present, trust principal is a 12-digit AWS account ARN
                           → WARN  (may be valid from mgmt account — customer must verify)
    - Role present, trust is a service principal, wildcard, or unrecognised format
                           → FAIL  (wrong trust — will block enrollment)

    NOTE: A VALID CT execution role trusts the MANAGEMENT ACCOUNT ROOT:
      arn:aws:iam::<mgmt_account_id>:root
    It does NOT contain the word "controltower" in the principal — that was
    the inverted logic in earlier versions.
    """
    resp, err = api(iam_client.get_role, RoleName="AWSControlTowerExecution")

    if err and "NoSuchEntity" in str(err):
        record("IAM", "AWSControlTowerExecution Role", PASS,
               "Role does not exist. Control Tower will create it during enrollment.")
        emit("AWSControlTowerExecution Role", PASS, "Not present — CT will create it (expected)")
        return

    if err:
        record("IAM", "AWSControlTowerExecution Role", WARN,
               f"Could not check role: {err}",
               "Manually verify: aws iam get-role --role-name AWSControlTowerExecution")
        emit("AWSControlTowerExecution Role", WARN, f"Check failed: {err}")
        return

    role       = resp["Role"]
    arn        = role.get("Arn", "")
    trust_doc  = role.get("AssumeRolePolicyDocument", {})
    trust_json = json.dumps(trust_doc, indent=2)

    # Extract all principal ARNs from the trust policy
    aws_principals = []
    for stmt in trust_doc.get("Statement", []):
        principal = stmt.get("Principal", {})
        if isinstance(principal, dict):
            aws_p = principal.get("AWS", [])
            aws_principals.extend(aws_p if isinstance(aws_p, list) else [aws_p])
        elif isinstance(principal, str):
            aws_principals.append(principal)

    # A valid CT execution role principal looks like:
    #   arn:aws:iam::<12-digit-mgmt-account-id>:root
    import re as _re
    account_root_pattern = _re.compile(r'arn:aws:iam::\d{12}:root')
    valid_principals = [p for p in aws_principals if account_root_pattern.match(str(p))]
    has_service_or_wildcard = any(
        str(p) == "*" or "amazonaws.com" in str(p)
        for p in aws_principals
    )

    if valid_principals:
        # Trust policy looks correct — trusts a specific account root
        trusted_account = valid_principals[0].split("::")[1].split(":")[0]
        record("IAM", "AWSControlTowerExecution Role", WARN,
               f"Role EXISTS and trusts account: {trusted_account}\n"
               f"ARN: {arn}\n"
               f"Trust principals: {', '.join(valid_principals)}\n\n"
               "This role will be REUSED by CT if the trust matches the management account.\n"
               "CRITICAL: Verify that '{trusted_account}' IS your CT management account.\n"
               "If it is a DIFFERENT account, delete this role before enrollment.",
               f"Verify the trusted account ID matches your CT management account:\n"
               f"  aws sts get-caller-identity  (run from management account)\n"
               f"  Expected trust: arn:aws:iam::<mgmt_account_id>:root\n"
               f"  Actual trust  : {valid_principals[0]}\n\n"
               f"If trust account is WRONG:\n"
               f"  aws iam delete-role --role-name AWSControlTowerExecution")
        emit("AWSControlTowerExecution Role", WARN,
             f"Role EXISTS — trusts account {trusted_account} — verify this IS your CT management account")
    elif has_service_or_wildcard:
        record("IAM", "AWSControlTowerExecution Role", FAIL,
               f"Role EXISTS with a SERVICE or WILDCARD trust — this is invalid for CT.\n"
               f"ARN: {arn}\n"
               f"Trust principals: {', '.join(aws_principals) or 'none'}\n"
               f"Trust snippet:\n{trust_json[:400]}",
               "This role WILL BLOCK CT enrollment. CT requires the role to trust the\n"
               "management account root (arn:aws:iam::<mgmt_id>:root).\n"
               "Delete the role before enrollment:\n"
               "  # First detach all policies:\n"
               "  aws iam list-attached-role-policies --role-name AWSControlTowerExecution\n"
               "  aws iam detach-role-policy --role-name AWSControlTowerExecution --policy-arn <arn>\n"
               "  # Then delete:\n"
               "  aws iam delete-role --role-name AWSControlTowerExecution")
        emit("AWSControlTowerExecution Role", FAIL,
             "Role EXISTS with service/wildcard trust — MUST be deleted before enrollment")
    else:
        # Has principals but none match account:root pattern — suspicious
        record("IAM", "AWSControlTowerExecution Role", FAIL,
               f"Role EXISTS with UNRECOGNISED trust principals.\n"
               f"ARN: {arn}\n"
               f"Trust principals found: {', '.join(aws_principals) or 'none found'}\n"
               f"Expected format: arn:aws:iam::<mgmt_account_id>:root\n"
               f"Trust snippet:\n{trust_json[:400]}",
               "This role has an unexpected trust structure. CT enrollment will fail.\n"
               "Inspect the full trust policy:\n"
               "  aws iam get-role --role-name AWSControlTowerExecution \\\n"
               "    --query 'Role.AssumeRolePolicyDocument'\n\n"
               "If the trust principal does not match your CT management account root ARN,\n"
               "delete and let CT recreate it:\n"
               "  aws iam delete-role --role-name AWSControlTowerExecution")
        emit("AWSControlTowerExecution Role", FAIL,
             f"Role EXISTS with unrecognised trust — inspect and likely delete before enrollment")

def chk_org_access_role(iam_client):
    """
    Check for a cross-account access role that allows the management account
    to bootstrap CT enrollment into this member account.

    NOTE: AWSControlTowerExecution is intentionally EXCLUDED here — it is
    evaluated separately by chk_ct_execution_role with full trust-policy
    inspection. Including it here would create a false PASS when that role
    has a bad trust policy.
    """
    CANDIDATE_ROLES = ["OrganizationAccountAccessRole"]
    found = []
    for rname in CANDIDATE_ROLES:
        resp, err = api(iam_client.get_role, RoleName=rname)
        if resp:
            # Verify trust policy trusts an AWS account (not a service)
            trust_doc = resp["Role"].get("AssumeRolePolicyDocument", {})
            for stmt in trust_doc.get("Statement", []):
                principal = stmt.get("Principal", {})
                aws_p = principal.get("AWS", []) if isinstance(principal, dict) else []
                aws_p = aws_p if isinstance(aws_p, list) else [aws_p]
                import re as _re
                if any(_re.search(r'\d{12}', str(p)) for p in aws_p):
                    found.append(rname)
                    break

    if found:
        record("IAM", "Cross-Account Access Role", PASS,
               f"Found valid cross-account role(s): {', '.join(found)}\n"
               "Control Tower management account can bootstrap into this account.")
        emit("Cross-Account Access Role", PASS, f"Found: {', '.join(found)}")
    else:
        record("IAM", "Cross-Account Access Role", WARN,
               "OrganizationAccountAccessRole not found (or has no account-level trust).\n"
               "Control Tower needs a cross-account role to bootstrap enrollment.\n"
               "Note: AWSControlTowerExecution is checked separately — do not rely on it here.",
               "Create OrganizationAccountAccessRole if missing:\n"
               "  1. In the management account, use CloudFormation or CLI to create:\n"
               "     Role name: OrganizationAccountAccessRole\n"
               "     Trust:     arn:aws:iam::<MGMT_ACCOUNT_ID>:root\n"
               "     Policy:    AdministratorAccess\n"
               "  2. Or confirm with the management account admin that they can\n"
               "     assume a role in this account.")
        emit("Cross-Account Access Role", WARN,
             "OrganizationAccountAccessRole not found — CT may not be able to bootstrap")

def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]

def _list_all_roles(iam_client):
    marker = None
    roles = []
    while True:
        kwargs = {"MaxItems": 1000}
        if marker:
            kwargs["Marker"] = marker
        resp, err = api(iam_client.list_roles, **kwargs)
        if err:
            return None, err
        roles.extend(resp.get("Roles", []))
        if not resp.get("IsTruncated"):
            return roles, None
        marker = resp.get("Marker")

def chk_ct_role_artifacts(iam_client):
    roles, err = _list_all_roles(iam_client)
    if err:
        record("IAM", "Control Tower Baseline Role Artifacts", WARN,
               f"Could not enumerate IAM roles: {err}",
               "Manually review for pre-existing Control Tower role artifacts or service-linked role remnants.")
        emit("Control Tower Baseline Role Artifacts", WARN, str(err))
        return

    ct_named = []
    ct_service_linked = []
    for role in roles:
        name = role.get("RoleName", "?")
        path = role.get("Path", "")
        arn = role.get("Arn", "?")
        lname = name.lower()

        if name == "AWSControlTowerExecution":
            continue

        if lname.startswith("awscontroltower") or lname.startswith("aws-controltower") or "controltower" in lname:
            ct_named.append(f"{name} | path={path} | arn={arn}")
        elif path.startswith("/aws-service-role/") and "controltower" in lname:
            ct_service_linked.append(f"{name} | path={path} | arn={arn}")

    if not ct_named and not ct_service_linked:
        record("IAM", "Control Tower Baseline Role Artifacts", INFO,
               f"Scanned {len(roles)} IAM roles.\n"
               "No additional Control Tower-named roles or Control Tower service-linked role artifacts were found.",
               "This is separate from the cross-account trust inventory and only checks for baseline-style IAM artifacts.")
        emit("Control Tower Baseline Role Artifacts", INFO,
             f"Scanned {len(roles)} roles â€” no extra CT IAM artifacts found")
        return

    detail = [f"Scanned roles: {len(roles)}"]
    if ct_named:
        detail.append(f"Additional CT-named roles ({len(ct_named)}):")
        detail.extend([f"  - {line}" for line in ct_named[:20]])
    if ct_service_linked:
        detail.append(f"CT service-linked roles ({len(ct_service_linked)}):")
        detail.extend([f"  - {line}" for line in ct_service_linked[:20]])

    record("IAM", "Control Tower Baseline Role Artifacts", WARN,
           "\n".join(detail),
           "These artifacts can indicate prior Control Tower enrollment or partial baseline deployment.\n"
           "Review whether they are expected before re-enrolling this account.\n"
           "This check is artifact-focused and does not duplicate the trust-inventory check.")
    emit("Control Tower Baseline Role Artifacts", WARN,
         f"{len(ct_named) + len(ct_service_linked)} CT IAM artifacts found â€” review before enrollment")

def _extract_external_trusts(policy_doc: dict, account_id: str) -> list[dict]:
    findings = []
    for stmt in _as_list(policy_doc.get("Statement", [])):
        if stmt.get("Effect") != "Allow":
            continue

        actions = [str(a) for a in _as_list(stmt.get("Action", []))]
        relevant = [
            a for a in actions
            if a in (
                "sts:AssumeRole",
                "sts:AssumeRoleWithSAML",
                "sts:AssumeRoleWithWebIdentity",
                "sts:*",
                "*",
            )
        ]
        if not relevant:
            continue

        principal = stmt.get("Principal")
        if not principal:
            continue

        condition = stmt.get("Condition", {})
        aws_principals = []
        federated_principals = []
        service_principals = []

        if principal == "*":
            aws_principals = ["*"]
        elif isinstance(principal, dict):
            aws_principals = [str(p) for p in _as_list(principal.get("AWS", []))]
            federated_principals = [str(p) for p in _as_list(principal.get("Federated", []))]
            service_principals = [str(p) for p in _as_list(principal.get("Service", []))]
        else:
            aws_principals = [str(principal)]

        external_aws = []
        wildcard = False
        for p in aws_principals:
            if p == "*":
                wildcard = True
                external_aws.append(p)
                continue
            if p == account_id or f"::{account_id}:" in p or f"arn:aws:iam::{account_id}:root" == p:
                continue
            external_aws.append(p)

        cond_text = json.dumps(condition, sort_keys=True) if condition else ""
        org_scoped = "aws:PrincipalOrgID" in cond_text

        if external_aws or federated_principals or org_scoped:
            findings.append({
                "actions": relevant,
                "external_aws": external_aws,
                "federated": federated_principals,
                "services": service_principals,
                "wildcard": wildcard,
                "org_scoped": org_scoped,
                "condition": condition,
            })
    return findings

def chk_trust_inventory(iam_client, account_id: str):
    """
    Inventory all IAM roles with cross-account or federated trust paths.

    PURPOSE FOR CT ENROLLMENT:
    CT enrollment does not remove or modify any existing role trusts.
    Post-enrollment, CT SCPs will restrict what assumed sessions can DO
    inside this account — but they do not revoke the ability to ASSUME roles.
    This check surfaces trusts so the customer can verify each is intentional
    before SCPs change the effective permissions of those assumed sessions.

    CATEGORISATION:
    Roles are split into four groups to make the output actionable:

    1. EXPECTED — Known AWS service/CT patterns, SSO permission sets, Cognito:
       No action needed. These are standard.

    2. CT PRIOR ENROLLMENT — CT baseline roles from a previous landing zone:
       Informational — confirms prior enrollment (already surfaced by other checks).

    3. VERIFY — Unrecognised external account trusts worth confirming:
       Customer should confirm the account ID is their own and the trust is intended.

    4. WILDCARD — Trust to * (any principal):
       Always FAIL — unrestricted assumption.
    """
    import re as _re

    roles, err = _list_all_roles(iam_client)
    if err:
        record("IAM", "Cross-Account Trust Inventory", WARN,
               f"Could not enumerate IAM roles: {err}",
               "Manually review IAM role trust policies for external or federated principals.")
        emit("Cross-Account Trust Inventory", WARN, str(err))
        return

    scanned = len(roles)

    # Known-safe patterns — no action needed
    EXPECTED_ROLE_PATTERNS = [
        # IAM Identity Center (SSO) permission sets
        r"AWSReservedSSO_",
        # Cognito Identity Pool roles
        r".*Cognito.*",
        # AppStream SSO
        r".*appstream.*sso.*",
        r".*app_stream.*sso.*",
    ]
    EXPECTED_PRINCIPAL_PATTERNS = [
        # AWS SSO / IAM Identity Center SAML providers in same account
        f"arn:aws:iam::{account_id}:saml-provider/AWSSSO",
        f"arn:aws:iam::{account_id}:saml-provider/AWS_SSO",
        # AWS Cognito
        "cognito-identity.amazonaws.com",
        # AWS services (service principals)
        "amazonaws.com",
    ]
    # CT baseline role name patterns
    CT_ROLE_PATTERNS = [
        r"aws-controltower-",
        r"AWSControlTowerExecution",
    ]
    # AWS organisation/platform role names that are typically expected
    PLATFORM_ROLE_PATTERNS = [
        r"AWSCloudFormationStackSetExecutionRole",
        r"AWS-SystemsManager-AutomationExecutionRole",
        r"OrganizationAccountAccessRole",
    ]

    def _is_expected(role_name: str, principals: list) -> bool:
        for pat in EXPECTED_ROLE_PATTERNS:
            if _re.search(pat, role_name, _re.IGNORECASE):
                return True
        for p in principals:
            for pat in EXPECTED_PRINCIPAL_PATTERNS:
                if pat.lower() in str(p).lower():
                    return True
        return False

    def _is_ct_role(role_name: str) -> bool:
        return any(_re.search(pat, role_name, _re.IGNORECASE)
                   for pat in CT_ROLE_PATTERNS)

    def _is_platform_role(role_name: str) -> bool:
        return any(_re.search(pat, role_name, _re.IGNORECASE)
                   for pat in PLATFORM_ROLE_PATTERNS)

    cat_expected  = []   # Known safe — SSO, Cognito, same-account federation
    cat_ct        = []   # CT baseline roles from prior enrollment
    cat_platform  = []   # Org/platform roles (StackSets, SSM Automation)
    cat_verify    = []   # Unrecognised — customer should confirm
    cat_wildcard  = []   # Wildcard trust — always flag

    for role in roles:
        role_name  = role.get("RoleName", "?")
        policy_doc = role.get("AssumeRolePolicyDocument", {})
        trusts     = _extract_external_trusts(policy_doc, account_id)
        if not trusts:
            continue

        all_principals = []
        has_wildcard   = False
        has_federated  = False
        for t in trusts:
            all_principals.extend(t.get("external_aws", []))
            all_principals.extend(t.get("federated", []))
            if t.get("wildcard"):
                has_wildcard = True
            if t.get("federated"):
                has_federated = True

        entry = {
            "name":       role_name,
            "principals": all_principals,
            "federated":  has_federated,
        }

        if has_wildcard:
            cat_wildcard.append(entry)
        elif _is_ct_role(role_name):
            cat_ct.append(entry)
        elif _is_expected(role_name, all_principals):
            cat_expected.append(entry)
        elif _is_platform_role(role_name):
            cat_platform.append(entry)
        else:
            cat_verify.append(entry)

    total_external = (len(cat_expected) + len(cat_ct) + len(cat_platform)
                      + len(cat_verify) + len(cat_wildcard))

    if total_external == 0:
        record("IAM", "Cross-Account Trust Inventory", PASS,
               f"Scanned {scanned} IAM roles — no external or federated trust paths found.")
        emit("Cross-Account Trust Inventory", PASS,
             f"Scanned {scanned} roles — no external trust paths")
        return

    def _fmt_entries(entries, limit=10):
        lines = []
        for e in entries[:limit]:
            principals_short = [str(p)[:80] for p in e["principals"][:2]]
            lines.append(f"  {e['name']} → {', '.join(principals_short) or '(service/federated)'}")
        if len(entries) > limit:
            lines.append(f"  ... and {len(entries) - limit} more")
        return "\n".join(lines)

    detail_parts = [
        f"Scanned roles           : {scanned}",
        f"Roles with external trust: {total_external}",
        f"",
        f"CATEGORY BREAKDOWN:",
        f"",
    ]

    if cat_wildcard:
        detail_parts += [
            f"[FAIL] Wildcard trust (*) — {len(cat_wildcard)} role(s):",
            _fmt_entries(cat_wildcard),
            "",
        ]

    if cat_verify:
        detail_parts += [
            f"[VERIFY] Unrecognised external accounts — {len(cat_verify)} role(s):",
            "  These trusts are not recognised as standard AWS/CT patterns.",
            "  Confirm each account ID belongs to your organisation.",
            _fmt_entries(cat_verify),
            "",
        ]

    if cat_platform:
        detail_parts += [
            f"[EXPECTED] Org/platform roles — {len(cat_platform)} role(s):",
            "  Standard AWS multi-account patterns (StackSets, SSM Automation).",
            "  Verify the trusted account ID is your management/admin account.",
            _fmt_entries(cat_platform),
            "",
        ]

    if cat_ct:
        detail_parts += [
            f"[CT PRIOR] CT baseline roles from prior enrollment — {len(cat_ct)} role(s):",
            "  Confirms prior CT enrollment (already flagged by Config/CFN checks).",
            _fmt_entries(cat_ct),
            "",
        ]

    if cat_expected:
        detail_parts += [
            f"[OK] Expected/known-safe — {len(cat_expected)} role(s):",
            "  SSO permission sets, Cognito Identity Pools, AppStream — no action.",
            _fmt_entries(cat_expected),
        ]

    detail = "\n".join(detail_parts)

    # Action text
    action_parts = []
    if cat_wildcard:
        action_parts.append(
            "CRITICAL — Wildcard trust roles:\n"
            "  Any principal can assume these roles. Review immediately:\n"
            + "\n".join(f"  aws iam get-role --role-name {e['name']}" for e in cat_wildcard[:5])
        )
    if cat_verify:
        action_parts.append(
            "VERIFY — Unrecognised external account trusts:\n"
            "  For each role, confirm the trusted account ID is your organisation's:\n"
            + "\n".join(f"  {e['name']} → {', '.join(str(p)[:60] for p in e['principals'][:1])}"
                        for e in cat_verify[:10])
            + "\n\n  Post-enrollment: CT SCPs may restrict what these sessions can do.\n"
              "  If any external account was relying on actions CT SCPs block\n"
              "  (e.g. deleting CloudTrail, modifying Config), those will break."
        )
    if cat_platform:
        action_parts.append(
            "PLATFORM ROLES — verify trusted account is your management/admin account:\n"
            + "\n".join(f"  {e['name']} → {', '.join(str(p)[:60] for p in e['principals'][:1])}"
                        for e in cat_platform[:5])
        )
    if not action_parts:
        action_parts.append(
            "No action required — all external trusts are in expected/CT categories.\n"
            "Post-enrollment: CT SCPs may limit what assumed sessions can do,\n"
            "but they do not revoke the ability to assume these roles."
        )

    severity = FAIL if cat_wildcard else (WARN if cat_verify else INFO)

    record("IAM", "Cross-Account Trust Inventory", severity, detail,
           "\n\n".join(action_parts))
    emit("Cross-Account Trust Inventory", severity,
         f"{scanned} roles scanned | "
         f"{len(cat_wildcard)} wildcard | "
         f"{len(cat_verify)} verify | "
         f"{len(cat_platform)} platform | "
         f"{len(cat_ct)} CT-prior | "
         f"{len(cat_expected)} expected-ok")

def chk_ct_baseline_stack_artifacts(cf_client, region: str):
    resp, err = api(cf_client.list_stacks,
                    StackStatusFilter=[
                        "CREATE_COMPLETE", "UPDATE_COMPLETE",
                        "ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
                        "CREATE_IN_PROGRESS", "REVIEW_IN_PROGRESS"
                    ])
    if err:
        record("CloudFormation", f"CT Baseline Stack Artifacts [{region}]", WARN,
               f"Could not list stacks for baseline artifact check: {err}", region=region)
        emit(f"CT Baseline Stack Artifacts [{region}]", WARN, str(err))
        return

    baseline_prefixes = [
        "AWSControlTowerBP-BASELINE-CLOUDTRAIL",
        "AWSControlTowerBP-BASELINE-CLOUDWATCH",
        "AWSControlTowerBP-BASELINE-CONFIG",
        "AWSControlTowerBP-BASELINE-ROLES",
        "AWSControlTowerBP-BASELINE-SERVICE-ROLES",
        "AWSControlTowerBP-BASELINE-SERVICE-LINKED-ROLES",
        "AWSControlTowerBP-VPC-ACCOUNT-FACTORY-V1",
    ]

    matched = []
    for stack in resp.get("StackSummaries", []):
        name = stack.get("StackName", "")
        if any(name.startswith(prefix) or name.startswith(f"StackSet-{prefix}") for prefix in baseline_prefixes):
            matched.append(name)

    if matched:
        record("CloudFormation", f"CT Baseline Stack Artifacts [{region}]", WARN,
               f"Found {len(matched)} explicit Control Tower baseline stack artifacts in {region}:\n  " +
               "\n  ".join(matched),
               "These map directly to Control Tower baseline deployment templates for CloudTrail, CloudWatch, Config, roles, service roles, service-linked roles, or Account Factory VPC setup.\n"
               "Their presence usually indicates prior enrollment or partial baseline deployment in this member account.\n"
               "Review before re-enrollment rather than treating them as generic CloudFormation stacks.",
               region=region)
        emit(f"CT Baseline Stack Artifacts [{region}]", WARN,
             f"Found {len(matched)} explicit CT baseline stack artifacts")
    else:
        record("CloudFormation", f"CT Baseline Stack Artifacts [{region}]", INFO,
               f"No explicit AWSControlTowerBP baseline stack artifacts found in {region}.",
               region=region)
        emit(f"CT Baseline Stack Artifacts [{region}]", INFO,
             "No explicit CT baseline stack artifacts found")

def chk_root_mfa(iam_client):
    resp, err = api(iam_client.get_account_summary)
    if err:
        record("IAM", "Root MFA Status", WARN, f"Could not retrieve account summary: {err}",
               "Manually check: AWS Console → Root user → Security Credentials → MFA")
        emit("Root MFA Status", WARN, str(err))
        return

    summary        = resp.get("SummaryMap", {})
    mfa_enabled    = summary.get("AccountMFAEnabled", 0)
    has_access_key = summary.get("AccountAccessKeysPresent", 0)
    users          = summary.get("Users", 0)
    roles          = summary.get("Roles", 0)
    roles_quota    = summary.get("RolesQuota", 1000)

    # MFA
    if mfa_enabled:
        record("IAM", "Root MFA Status", PASS,
               "Root MFA is enabled. CT mandatory detective guardrail will pass.")
        emit("Root MFA Status", PASS, "Root MFA enabled")
    else:
        record("IAM", "Root MFA Status", FAIL,
               "Root MFA is NOT enabled.\n"
               "CT mandatory guardrail 'Detect whether MFA for the root account is enabled' "
               "will immediately flag this account as NON-COMPLIANT.",
               "Enable root MFA BEFORE enrollment:\n"
               "  1. Sign in as root user\n"
               "  2. AWS Console → Security Credentials → Multi-factor Authentication\n"
               "  3. Assign a virtual or hardware MFA device")
        emit("Root MFA Status", FAIL,
             "Root MFA NOT enabled — will be flagged by mandatory CT guardrail")

    # Root access keys
    if has_access_key:
        record("IAM", "Root Access Keys", FAIL,
               "Root account has ACTIVE access keys — security violation.",
               "Delete root access keys immediately:\n"
               "  AWS Console → Root user → Security Credentials → Access keys → Delete")
        emit("Root Access Keys", FAIL, "Active root access keys found — delete them now")
    else:
        record("IAM", "Root Access Keys", PASS, "No root access keys (correct).")
        emit("Root Access Keys", PASS, "No root access keys")

    # IAM role quota
    pct = (roles / roles_quota * 100) if roles_quota else 0
    if pct < 85:
        record("IAM", "IAM Role Count", PASS,
               f"{roles}/{roles_quota} roles used ({pct:.0f}%). CT adds ~5 roles.")
        emit("IAM Role Count", PASS, f"{roles}/{roles_quota} ({pct:.0f}%) — headroom OK")
    elif pct < 95:
        record("IAM", "IAM Role Count", WARN,
               f"{roles}/{roles_quota} roles used ({pct:.0f}%). CT will add ~5 more — nearing limit.",
               "Open a Service Quotas request for 'IAM roles per account' before enrollment.")
        emit("IAM Role Count", WARN, f"{roles}/{roles_quota} ({pct:.0f}%) — approaching limit")
    else:
        record("IAM", "IAM Role Count", FAIL,
               f"{roles}/{roles_quota} roles used ({pct:.0f}%). Adding CT roles will exceed quota.",
               "Request quota increase immediately:\n"
               "  AWS Console → Service Quotas → IAM → Roles per account")
        emit("IAM Role Count", FAIL, f"{roles}/{roles_quota} ({pct:.0f}%) — CRITICAL, will exceed quota")

def chk_iam_password_policy(iam_client):
    resp, err = api(iam_client.get_account_password_policy)
    if err and "NoSuchEntity" in str(err):
        record("IAM", "Password Policy", WARN,
               "No custom password policy set. CT detective guardrail may flag this.",
               "Set a password policy that meets CT recommendations:\n"
               "  Min length: 14, require uppercase, lowercase, numbers, symbols\n"
               "  aws iam update-account-password-policy --minimum-password-length 14 ...")
        emit("Password Policy", WARN, "No password policy — CT guardrail will flag this")
        return
    if err:
        record("IAM", "Password Policy", WARN, f"Could not check: {err}")
        emit("Password Policy", WARN, str(err))
        return

    pol = resp.get("PasswordPolicy", {})
    issues = []
    if pol.get("MinimumPasswordLength", 0) < 14:
        issues.append(f"MinLength={pol.get('MinimumPasswordLength')} (CT recommends ≥14)")
    if not pol.get("RequireUppercaseCharacters"):
        issues.append("Missing: RequireUppercase")
    if not pol.get("RequireLowercaseCharacters"):
        issues.append("Missing: RequireLowercase")
    if not pol.get("RequireNumbers"):
        issues.append("Missing: RequireNumbers")
    if not pol.get("RequireSymbols"):
        issues.append("Missing: RequireSymbols")

    if issues:
        record("IAM", "Password Policy", WARN,
               "Password policy exists but may not meet CT guardrail requirements:\n  " +
               "\n  ".join(issues),
               "Strengthen password policy to avoid non-compliance flags post-enrollment.")
        emit("Password Policy", WARN, f"{len(issues)} policy gaps: {'; '.join(issues)}")
    else:
        record("IAM", "Password Policy", PASS,
               "Password policy meets CT detective guardrail requirements.")
        emit("Password Policy", PASS, "Password policy meets CT standards")


# ─── SECTION 3: AWS CONFIG CHECKS ────────────────────────────────────────────

def chk_config_recorder(config_client, region: str):
    """
    Evaluate the Config recorder state for CT enrollment readiness.

    Naming logic:
      - No recorder            → PASS  (CT will create its own)
      - CT baseline name found → FAIL  (indicates prior partial/broken enrollment;
                                        CT cannot enroll fresh over this state)
      - Any other name found   → FAIL  (foreign recorder will conflict with CT)

    Why CT baseline name = FAIL not WARN:
      When aws-controltower-BaselineConfigRecorder exists in an account that is NOT
      currently enrolled (as diagnosed by the AWSControlTowerExecution role check),
      it means a previous enrollment attempt was incomplete or the account was
      unenrolled without cleanup. CT's enrollment workflow will attempt to create
      or update this recorder and may fail unpredictably depending on its current
      state. The customer MUST resolve this with AWS Support or by following the
      CT re-enrollment documentation before proceeding.
    """
    resp, err = api(config_client.describe_configuration_recorders)
    if err:
        record("AWS Config", "Configuration Recorder", WARN,
               f"Could not check recorders in {region}: {err}", region=region)
        emit(f"Config Recorder [{region}]", WARN, str(err))
        return False

    recorders = resp.get("ConfigurationRecorders", [])
    if not recorders:
        record("AWS Config", "Configuration Recorder", PASS,
               f"No recorder exists in {region}. CT will create one during enrollment.",
               region=region)
        emit(f"Config Recorder [{region}]", PASS,
             "No recorder — CT will create one (expected)")
        return True

    # Check recorder status too
    status_resp, _ = api(config_client.describe_configuration_recorder_status)
    recorder_statuses = {
        s.get("name"): s.get("recording", False)
        for s in (status_resp.get("ConfigurationRecordersStatus", []) if status_resp else [])
    }

    for rec in recorders:
        name      = rec.get("name", "?")
        role_arn  = rec.get("roleARN", "?")
        grp       = rec.get("recordingGroup", {})
        scope     = "ALL_SUPPORTED_RESOURCES" if grp.get("allSupported") else \
                    f"{len(grp.get('resourceTypes', []))} specific resource types only"
        recording = recorder_statuses.get(name, "unknown")

        if name == CT_BASELINE_CONFIG_RECORDER:
            action = (
                "This recorder name matches the CT baseline but enrollment is NOT active.\n"
                "This indicates a PARTIAL or BROKEN prior CT enrollment that was not\n"
                "properly cleaned up. CT cannot re-enroll cleanly over this state.\n\n"
                "REQUIRED remediation steps (do NOT delete blindly):\n"
                "  1. Check if this account was previously enrolled: AWS CT Console → Accounts\n"
                "  2. If previously enrolled: follow CT unenrollment procedure first\n"
                "     https://docs.aws.amazon.com/controltower/latest/userguide/unenroll-account.html\n"
                "  3. If partial/failed enrollment: open an AWS Support case referencing:\n"
                "     'Control Tower baseline Config recorder cleanup before re-enrollment'\n"
                "  4. After cleanup confirmed by AWS Support:\n"
                f"     aws configservice delete-configuration-recorder \\\n"
                f"       --configuration-recorder-name {name} --region {region}\n\n"
                f"Reference: {CT_EXISTING_CONFIG_DOC}"
            )
            detail = (
                f"Region    : {region}\n"
                f"Name      : {name}  ← CT baseline name (no active enrollment)\n"
                f"Role ARN  : {role_arn}\n"
                f"Scope     : {scope}\n"
                f"Recording : {recording}\n\n"
                "DIAGNOSIS: CT baseline recorder exists without active enrollment.\n"
                "This is a BROKEN STATE from a prior partial or unenrolled CT deployment.\n"
                "A fresh CT enrollment will fail or behave unpredictably in this state."
            )
        else:
            action = (
                f"A non-CT recorder '{name}' exists and WILL conflict with CT enrollment.\n"
                "Only ONE configuration recorder is allowed per region per account.\n\n"
                "Steps:\n"
                f"  1. Back up existing Config data if needed\n"
                f"  2. Delete the recorder:\n"
                f"     aws configservice delete-configuration-recorder \\\n"
                f"       --configuration-recorder-name {name} --region {region}\n"
                f"  3. CT will create its own recorder during enrollment\n\n"
                f"Reference: {CT_EXISTING_CONFIG_DOC}"
            )
            detail = (
                f"Region    : {region}\n"
                f"Name      : {name}  ← non-CT recorder\n"
                f"Role ARN  : {role_arn}\n"
                f"Scope     : {scope}\n"
                f"Recording : {recording}\n\n"
                "This recorder will block CT enrollment — only one recorder allowed per region."
            )

        record("AWS Config", f"Configuration Recorder: '{name}'", FAIL,
               detail, action, region=region)
        emit(f"Config Recorder '{name}' [{region}]", FAIL,
             f"EXISTS — WILL BLOCK enrollment ({'CT baseline in broken state' if name == CT_BASELINE_CONFIG_RECORDER else 'foreign recorder'})")
    return False

def chk_config_delivery_channel(config_client, region: str):
    """
    Evaluate Config delivery channel for CT enrollment readiness.
    Same logic as recorder: CT baseline name without active enrollment = FAIL (broken state).
    """
    resp, err = api(config_client.describe_delivery_channels)
    if err:
        record("AWS Config", "Delivery Channel", WARN,
               f"Could not check delivery channels in {region}: {err}", region=region)
        emit(f"Config Delivery Channel [{region}]", WARN, str(err))
        return

    channels = resp.get("DeliveryChannels", [])
    if not channels:
        record("AWS Config", "Delivery Channel", PASS,
               f"No delivery channel in {region}. CT will create one during enrollment.",
               region=region)
        emit(f"Config Delivery Channel [{region}]", PASS,
             "No channel — CT will create one (expected)")
        return

    for ch in channels:
        name   = ch.get("name", "?")
        bucket = ch.get("s3BucketName", "?")
        sns    = ch.get("snsTopicARN", "N/A")
        freq   = ch.get("configSnapshotDeliveryProperties", {}).get("deliveryFrequency", "N/A")

        if name == CT_BASELINE_CONFIG_DELIVERY_CHANNEL:
            action = (
                "This delivery channel name matches the CT baseline but enrollment is NOT active.\n"
                "This indicates a PARTIAL or BROKEN prior CT enrollment.\n\n"
                "REQUIRED remediation steps:\n"
                "  1. Confirm prior enrollment status in AWS CT Console → Accounts\n"
                "  2. If previously enrolled: follow CT unenrollment procedure:\n"
                "     https://docs.aws.amazon.com/controltower/latest/userguide/unenroll-account.html\n"
                "  3. If partial/failed enrollment: open AWS Support case\n"
                "  4. After confirmed cleanup:\n"
                f"     aws configservice delete-delivery-channel \\\n"
                f"       --delivery-channel-name {name} --region {region}\n"
                f"  NOTE: Save any needed logs from '{bucket}' before deleting.\n\n"
                f"Reference: {CT_EXISTING_CONFIG_DOC}"
            )
            detail = (
                f"Region    : {region}\n"
                f"Name      : {name}  ← CT baseline name (no active enrollment)\n"
                f"S3 Bucket : {bucket}\n"
                f"SNS Topic : {sns}\n"
                f"Frequency : {freq}\n\n"
                "DIAGNOSIS: CT baseline delivery channel exists without active enrollment.\n"
                "This is a BROKEN STATE — enrollment will fail or behave unpredictably."
            )
            emit_msg = "CT baseline delivery channel in broken state — WILL BLOCK enrollment"
        else:
            action = (
                f"Foreign delivery channel '{name}' will BLOCK CT enrollment.\n"
                "Only ONE delivery channel allowed per region per account.\n\n"
                "Steps:\n"
                f"  1. Save logs from '{bucket}' if needed\n"
                f"  2. Delete the channel:\n"
                f"     aws configservice delete-delivery-channel \\\n"
                f"       --delivery-channel-name {name} --region {region}\n"
                "  3. CT creates its own channel pointing to the Log Archive account bucket\n\n"
                f"Reference: {CT_EXISTING_CONFIG_DOC}"
            )
            detail = (
                f"Region    : {region}\n"
                f"Name      : {name}  ← non-CT delivery channel\n"
                f"S3 Bucket : {bucket}\n"
                f"SNS Topic : {sns}\n"
                f"Frequency : {freq}\n\n"
                "This channel will block CT enrollment — only one allowed per region."
            )
            emit_msg = f"Foreign delivery channel exists — WILL BLOCK enrollment. Bucket: {bucket}"

        record("AWS Config", f"Delivery Channel: '{name}'", FAIL,
               detail, action, region=region)
        emit(f"Config Delivery Channel '{name}' [{region}]", FAIL, emit_msg)

def chk_config_rules(config_client, region: str):
    resp, err = api(config_client.describe_config_rules)
    if err:
        record("AWS Config", "Config Rules Inventory", WARN,
               f"Could not list Config rules in {region}: {err}", region=region)
        emit(f"Config Rules [{region}]", WARN, str(err))
        return

    rules = resp.get("ConfigRules", [])
    if not rules:
        record("AWS Config", "Config Rules Inventory", INFO,
               f"No Config rules in {region}.", region=region)
        emit(f"Config Rules [{region}]", INFO, "No rules")
        return

    # Detect overlaps with CT mandatory/recommended detective guardrails
    CT_GUARDRAIL_PATTERNS = [
        "root-account-mfa",
        "root-account-hardware-mfa",
        "cloudtrail-enabled",
        "cloud-trail-encryption",
        "cloud-trail-log-file",
        "iam-password-policy",
        "access-keys-rotated",
        "iam-root-access-key-check",
        "iam-user-mfa-enabled",
        "mfa-enabled-for-iam-console",
        "s3-bucket-logging-enabled",
        "s3-bucket-server-side-encryption",
        "s3-bucket-public-read-prohibited",
        "s3-bucket-public-write-prohibited",
        "ebs-snapshot-public-restorable",
        "ec2-instances-in-vpc",
        "vpc-flow-logs-enabled",
        "ec2-security-group-attached-to-eni",
        "restricted-ssh",
        "restricted-common-ports",
        "iam-policy-no-statements-with-admin-access",
        "guardduty-enabled-centralized",
    ]

    managed = [r for r in rules if r.get("Source", {}).get("Owner") == "AWS"]
    custom  = [r for r in rules if r.get("Source", {}).get("Owner") != "AWS"]
    overlaps = [r for r in managed
                if any(p in r.get("ConfigRuleName", "").lower()
                       for p in CT_GUARDRAIL_PATTERNS)]

    all_names = [r.get("ConfigRuleName", "?") for r in rules]
    overlap_names = [r.get("ConfigRuleName", "?") for r in overlaps]

    detail = (
        f"Region: {region}\n"
        f"Total rules      : {len(rules)}\n"
        f"AWS Managed      : {len(managed)}\n"
        f"Custom (Lambda)  : {len(custom)}\n"
        f"CT guardrail overlaps (duplicate evaluations): {len(overlaps)}\n\n"
        f"All rules:\n  " + "\n  ".join(all_names)
    )
    if overlaps:
        detail += f"\n\nOverlapping with CT guardrails:\n  " + "\n  ".join(overlap_names)

    status = WARN if overlaps or custom else INFO
    action = ""
    if overlaps:
        action = (
            f"Rules do NOT block enrollment, but will cause:\n"
            f"  • Duplicate Config evaluations (double cost)\n"
            f"  • Confusing dual compliance dashboards\n\n"
            f"Post-enrollment recommended action: remove these {len(overlaps)} rules\n"
            f"that are now covered by CT guardrails:\n  " +
            "\n  ".join(overlap_names)
        )
    if custom:
        action += (
            f"\n\nCustom rules ({len(custom)}) will continue to run post-enrollment.\n"
            f"Review each to ensure they do not conflict with CT guardrails."
        )

    record("AWS Config", f"Config Rules Inventory [{region}]", status, detail, action,
           region=region)
    emit(f"Config Rules [{region}]", status,
         f"{len(rules)} rules | {len(overlaps)} CT overlaps | {len(custom)} custom")

def chk_config_cost_estimate(config_client, region: str):
    resp, err = api(config_client.get_discovered_resource_counts)
    if err:
        record("Cost Estimate", f"Config CI Cost [{region}]", WARN,
               f"Could not retrieve resource counts: {err}", region=region)
        emit(f"Config CI Cost [{region}]", WARN, str(err))
        return

    total = resp.get("totalDiscoveredResources", 0)
    # CT enables ALL_SUPPORTED_RESOURCES — estimate ~10 Config Items/resource/month
    # Price: $0.003 per CI
    est_ci   = total * 10
    est_cost = est_ci * 0.003

    resource_counts = resp.get("resourceCounts", [])
    top_types = sorted(resource_counts, key=lambda x: x.get("count", 0), reverse=True)[:8]
    type_lines = [f"{t.get('resourceType','?'):50s} {t.get('count',0):>6,}" for t in top_types]

    detail = (
        f"Region: {region}\n"
        f"Discovered resources : {total:,}\n"
        f"Est. Config Items/mo : ~{est_ci:,}\n"
        f"Est. Config cost/mo  : ~${est_cost:,.2f} (at $0.003/CI)\n\n"
        f"Top resource types:\n  " +
        "\n  ".join(type_lines) if type_lines else ""
    )

    if est_cost < 200:
        status = INFO
        action = "Config cost impact is low. No action required."
    elif est_cost < 1000:
        status = WARN
        action = (
            f"Config cost will increase to ~${est_cost:,.0f}/mo.\n"
            "Post-enrollment: review recording scope — disable resource types not needed for compliance."
        )
    else:
        status = WARN
        action = (
            f"SIGNIFICANT Config cost: ~${est_cost:,.0f}/mo.\n"
            "Post-enrollment REQUIRED: review and restrict Config recording scope.\n"
            "Consider recording only resources relevant to your compliance framework."
        )

    record("Cost Estimate", f"Config CI Cost [{region}]", status, detail, action, region=region)
    emit(f"Config CI Cost [{region}]", status,
         f"{total:,} resources → ~${est_cost:,.0f}/mo new Config cost")


# ─── SECTION 4: CLOUDTRAIL CHECKS ────────────────────────────────────────────

def chk_cloudtrail(ct_client, region: str):
    resp, err = api(ct_client.describe_trails, includeShadowTrails=False)
    if err:
        record("CloudTrail", f"Trails [{region}]", WARN,
               f"Could not describe trails: {err}", region=region)
        emit(f"CloudTrail Trails [{region}]", WARN, str(err))
        return

    trails = resp.get("trailList", [])
    if not trails:
        record("CloudTrail", f"Trails [{region}]", INFO,
               f"No trails in {region}. CT will create an org-level multi-region trail.",
               region=region)
        emit(f"CloudTrail Trails [{region}]", INFO,
             "No trails — CT org trail will cover this account (OK)")
        return

    for trail in trails:
        name         = trail.get("Name", "?")
        home         = trail.get("HomeRegion", "?")
        is_multi     = trail.get("IsMultiRegionTrail", False)
        is_org       = trail.get("IsOrganizationTrail", False)
        s3_bucket    = trail.get("S3BucketName", "?")
        has_cw_logs  = bool(trail.get("CloudWatchLogsLogGroupArn"))
        log_valid    = trail.get("LogFileValidationEnabled", False)

        # Check if trail is active
        status_resp, _ = api(ct_client.get_trail_status, Name=name)
        is_logging = status_resp.get("IsLogging", False) if status_resp else "unknown"

        # Check event selectors for data events
        sel_resp, _ = api(ct_client.get_event_selectors, TrailName=name)
        event_selectors = sel_resp.get("EventSelectors", []) if sel_resp else []
        has_data_events = any(
            es.get("DataResources") for es in event_selectors
        )

        risks = []
        if is_multi:
            risks.append("Multi-region trail duplicates CT org trail → double event cost")
        if is_org:
            risks.append("Org trail — coordinate with CT org trail to avoid 2 org trails")
        if has_cw_logs:
            risks.append("CW Logs integration — update SIEM/log pipelines after enrollment")
        if has_data_events:
            risks.append("Data events enabled — CT org trail does NOT enable data events by default; reconfigure post-enrollment to avoid gap")

        detail = (
            f"Name              : {name}\n"
            f"Home Region       : {home}\n"
            f"S3 Bucket         : {s3_bucket}\n"
            f"Multi-Region      : {is_multi}\n"
            f"Org Trail         : {is_org}\n"
            f"Currently Logging : {is_logging}\n"
            f"Log Validation    : {log_valid}\n"
            f"CW Logs           : {has_cw_logs}\n"
            f"Data Events       : {has_data_events}"
            + (f"\n\nRisks:\n  • " + "\n  • ".join(risks) if risks else "")
        )
        action = (
            "Post-enrollment checklist for this trail:\n"
            "  1. Confirm CT org trail is active and logging for this account.\n"
            "  2. Evaluate deleting this trail to avoid duplicate costs.\n"
            "  3. If data events were enabled here, re-enable on the CT org trail.\n"
            "  4. Update any SIEM/log pipeline that consumes this trail's S3 bucket.\n"
            "  5. Adjust CloudWatch Logs metric filters if the log group changes."
        ) if risks else (
            "Low risk. Post-enrollment: evaluate consolidating into CT org trail."
        )
        status = WARN if risks else INFO
        record("CloudTrail", f"Trail '{name}' [{region}]", status, detail, action, region=region)
        emit(f"CloudTrail '{name}' [{region}]", status,
             f"s3={s3_bucket} | multi={is_multi} | org={is_org} | data_events={has_data_events}")


# ─── SECTION 5: NETWORKING / EC2 CHECKS ─────────────────────────────────────

def chk_open_security_groups(ec2_client, region: str):
    """Detect SGs with unrestricted SSH/RDP — CT detective guardrail will flag these."""
    resp, err = api(ec2_client.describe_security_groups)
    if err:
        record("Networking", f"Security Groups [{region}]", WARN,
               f"Could not list security groups: {err}", region=region)
        emit(f"Security Groups [{region}]", WARN, str(err))
        return

    sgs = resp.get("SecurityGroups", [])
    open_ssh = []
    open_rdp = []

    for sg in sgs:
        sg_id   = sg.get("GroupId", "?")
        sg_name = sg.get("GroupName", "?")
        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort", 0)
            to_port   = perm.get("ToPort", 65535)
            for ip in perm.get("IpRanges", []):
                if ip.get("CidrIp") == "0.0.0.0/0":
                    if from_port <= 22 <= to_port:
                        open_ssh.append(f"{sg_id} ({sg_name})")
                    if from_port <= 3389 <= to_port:
                        open_rdp.append(f"{sg_id} ({sg_name})")
            for ip6 in perm.get("Ipv6Ranges", []):
                if ip6.get("CidrIpv6") == "::/0":
                    if from_port <= 22 <= to_port:
                        open_ssh.append(f"{sg_id} ({sg_name}) [IPv6]")
                    if from_port <= 3389 <= to_port:
                        open_rdp.append(f"{sg_id} ({sg_name}) [IPv6]")

    total_issues = len(open_ssh) + len(open_rdp)
    if total_issues == 0:
        record("Networking", f"Security Groups — Open SSH/RDP [{region}]", PASS,
               f"No security groups with unrestricted SSH (22) or RDP (3389) found in {region}.",
               region=region)
        emit(f"Security Groups — Open SSH/RDP [{region}]", PASS,
             f"{len(sgs)} SGs checked — no open SSH/RDP")
    else:
        lines = []
        if open_ssh:
            lines.append(f"Open SSH (port 22): {', '.join(open_ssh[:5])}")
        if open_rdp:
            lines.append(f"Open RDP (port 3389): {', '.join(open_rdp[:5])}")
        record("Networking", f"Security Groups — Open SSH/RDP [{region}]", WARN,
               f"Found {total_issues} security group(s) with unrestricted access in {region}:\n  " +
               "\n  ".join(lines),
               "CT detective guardrails 'restricted-ssh' and 'restricted-common-ports' will flag these.\n"
               "They are NOT blocked (detective only), but will appear as non-compliant in CT dashboard.\n"
               "Remediate by restricting source CIDR to known IP ranges.",
               region=region)
        emit(f"Security Groups — Open SSH/RDP [{region}]", WARN,
             f"{total_issues} SGs with open SSH/RDP — will be flagged by CT guardrails")

def chk_default_vpc(ec2_client, region: str):
    resp, err = api(ec2_client.describe_vpcs,
                    Filters=[{"Name": "isDefault", "Values": ["true"]}])
    if err:
        record("Networking", f"Default VPC [{region}]", WARN,
               f"Could not check default VPC: {err}", region=region)
        emit(f"Default VPC [{region}]", WARN, str(err))
        return

    vpcs = resp.get("Vpcs", [])
    if vpcs:
        vpc_id = vpcs[0].get("VpcId", "?")
        record("Networking", f"Default VPC [{region}]", WARN,
               f"Default VPC exists: {vpc_id} in {region}.\n"
               "CT elective guardrail 'Disallow Creation of Default VPCs' will flag this if enabled.",
               "If the CT OU has the 'delete default VPC' guardrail enabled, this will be flagged.\n"
               "Consider deleting the default VPC if it is not in use:\n"
               f"  aws ec2 delete-vpc --vpc-id {vpc_id} --region {region}\n"
               "(Delete all subnets, internet gateways, and route tables first.)",
               region=region)
        emit(f"Default VPC [{region}]", WARN,
             f"Default VPC {vpc_id} exists — may be flagged by elective guardrail")
    else:
        record("Networking", f"Default VPC [{region}]", PASS,
               f"No default VPC in {region}.", region=region)
        emit(f"Default VPC [{region}]", PASS, "No default VPC")


# ─── SECTION 6: CLOUDFORMATION CHECKS ───────────────────────────────────────

def chk_cloudformation(cf_client, region: str):
    resp, err = api(cf_client.list_stacks,
                    StackStatusFilter=[
                        "CREATE_COMPLETE", "UPDATE_COMPLETE",
                        "ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
                        "CREATE_IN_PROGRESS", "REVIEW_IN_PROGRESS"
                    ])
    if err:
        record("CloudFormation", f"Stack Check [{region}]", WARN,
               f"Could not list stacks: {err}", region=region)
        emit(f"CloudFormation [{region}]", WARN, str(err))
        return

    stacks = resp.get("StackSummaries", [])
    ct_stacks = [s for s in stacks
                 if "controltower" in s.get("StackName", "").lower() or
                    "awscontroltower" in s.get("StackName", "").lower()]
    total = len(stacks)

    if ct_stacks:
        names = [s["StackName"] for s in ct_stacks]
        record("CloudFormation", f"CT Stack Remnants [{region}]", WARN,
               f"Found {len(ct_stacks)} existing CT-related stacks in {region}:\n  " +
               "\n  ".join(names),
               "These may indicate a previous partial CT enrollment attempt.\n"
               "Investigate whether these are safe to delete or from a prior landing zone.\n"
               "Contact AWS Support if unsure.",
               region=region)
        emit(f"CT Stack Remnants [{region}]", WARN,
             f"Found {len(ct_stacks)} CT-related stacks — investigate before enrollment")
    elif total > 1800:
        record("CloudFormation", f"Stack Count [{region}]", WARN,
               f"{total} stacks — near the 2,000 limit. CT adds 3–5 stacks per region.",
               "Request a CloudFormation stack limit increase before enrollment.",
               region=region)
        emit(f"Stack Count [{region}]", WARN,
             f"{total} stacks — near limit. CT adds 3–5 per region.")
    else:
        record("CloudFormation", f"Stack Count [{region}]", PASS,
               f"{total} stacks in {region}. CT adds ~3–5 — well within limits.",
               region=region)
        emit(f"Stack Count [{region}]", PASS,
             f"{total} stacks — CT adds ~3–5 per region, headroom OK")


# ─── SECTION 7: COMMERCIAL CHECKS ────────────────────────────────────────────

def chk_reserved_instances(ec2_client, region: str):
    resp, err = api(ec2_client.describe_reserved_instances,
                    Filters=[{"Name": "state", "Values": ["active"]}])
    if err:
        record("Commercial", f"Reserved Instances [{region}]", WARN,
               f"Could not check RIs: {err}", region=region)
        emit(f"Reserved Instances [{region}]", WARN, str(err))
        return

    ris = resp.get("ReservedInstances", [])
    if not ris:
        record("Commercial", f"Reserved Instances [{region}]", INFO,
               f"No active Reserved Instances in {region}.", region=region)
        emit(f"Reserved Instances [{region}]", INFO, "No active RIs")
        return

    ri_lines = [
        f"{ri.get('InstanceCount',1)}x {ri.get('InstanceType','?')} "
        f"({ri.get('OfferingClass','?')}) expires {str(ri.get('End','?'))[:10]}"
        for ri in ris[:8]
    ]
    record("Commercial", f"Reserved Instances [{region}]", WARN,
           f"{len(ris)} active RIs in {region}:\n  " + "\n  ".join(ri_lines),
           "RIs remain with this account after enrollment — no data loss.\n"
           "ACTION: Verify RI sharing is enabled in the CT MANAGEMENT account:\n"
           "  Billing console → Preferences → Reserved Instance Sharing → ON\n"
           "If moving between Organizations (rare), RIs CANNOT be transferred.",
           region=region)
    emit(f"Reserved Instances [{region}]", WARN,
         f"{len(ris)} active RIs — verify RI sharing in management account")

def chk_savings_plans(session, region: str):
    if region != "us-east-1":
        return  # API only in us-east-1
    try:
        sp_client = session.client("savingsplans", region_name="us-east-1")
        resp, err = api(sp_client.describe_savings_plans, states=["active"])
        if err:
            record("Commercial", "Savings Plans", WARN,
                   f"Could not check Savings Plans: {err}",
                   "Manually check: AWS Console → Cost Management → Savings Plans")
            emit("Savings Plans", WARN, str(err))
            return

        plans = resp.get("savingsPlans", [])
        if not plans:
            record("Commercial", "Savings Plans", INFO,
                   "No active Savings Plans found.")
            emit("Savings Plans", INFO, "No Savings Plans")
            return

        plan_lines = [
            f"{p.get('savingsPlanType','?')} | ${p.get('commitment','?')}/hr "
            f"| Ends {str(p.get('end','?'))[:10]}"
            for p in plans[:5]
        ]
        record("Commercial", "Savings Plans", WARN,
               f"{len(plans)} active Savings Plans:\n  " + "\n  ".join(plan_lines),
               "Savings Plans remain with this account after enrollment.\n"
               "ACTION: Verify Savings Plans sharing is enabled in the CT management account:\n"
               "  Billing console → Savings Plans → Preferences → Savings Plans sharing → ON\n"
               "⚠ If moving between AWS Organizations, Savings Plans CANNOT be transferred.")
        emit("Savings Plans", WARN,
             f"{len(plans)} Savings Plans — verify org sharing in management account")
    except Exception:
        pass

def chk_support_plan(support_client):
    resp, err = api(support_client.describe_severity_levels, language="en")
    if err:
        if "SubscriptionRequiredException" in str(err):
            record("Commercial", "Support Plan", WARN,
                   "Account has Basic or Developer support plan.",
                   "After enrollment, the account will inherit support from the CT management account.\n"
                   "Ensure management account has Business or Enterprise support.\n"
                   "Verify with: AWS Console → Support → Support plans")
            emit("Support Plan", WARN, "Basic/Developer support — will inherit from CT management account")
        else:
            record("Commercial", "Support Plan", INFO,
                   f"Could not determine support tier: {err}")
            emit("Support Plan", INFO, f"Could not determine: {err}")
    else:
        record("Commercial", "Support Plan", PASS,
               "Account has Business or Enterprise support plan.")
        emit("Support Plan", PASS, "Business/Enterprise support confirmed")

def chk_manual_commercial():
    """Items that cannot be checked programmatically."""
    manuals = [
        {
            "check": "AWS Credits",
            "detail": (
                "AWS credits CANNOT be read via SDK/CLI.\n"
                "Credits tied to a specific Payer account do NOT automatically transfer\n"
                "if this account moves to a new Organization or management account."
            ),
            "action": (
                "MANUAL ACTION REQUIRED:\n"
                "  1. Go to AWS Billing Console → Credits for this account\n"
                "  2. Record all credits: amount, expiry date, applicable services\n"
                "  3. If credits are tied to the current payer, contact your AWS Account\n"
                "     Executive to arrange transfer BEFORE enrollment\n"
                "  4. Use/spend credits before migration if transfer is not possible\n"
                "  Risk: Credits may be LOST if payer account changes"
            )
        },
        {
            "check": "EDP (Enterprise Discount Program)",
            "detail": (
                "EDP discounts are attached to the Payer/Management account commitment.\n"
                "If this account moves under a DIFFERENT management account, EDP coverage\n"
                "must be explicitly confirmed with the AWS Account team."
            ),
            "action": (
                "MANUAL ACTION REQUIRED:\n"
                "  1. Contact your AWS Account Executive\n"
                "  2. Confirm EDP covers this account under the CT management account\n"
                "  3. Get written confirmation before proceeding\n"
                "  Risk: Loss of EDP discount (typically 10–30% of total AWS spend)"
            )
        },
        {
            "check": "Private Pricing Agreements (PPA)",
            "detail": (
                "PPAs are account or org-specific and do NOT automatically transfer\n"
                "when accounts move between Organizations."
            ),
            "action": (
                "MANUAL ACTION REQUIRED:\n"
                "  1. List all active PPAs with the AWS Account team\n"
                "  2. Request PPA transfer to the CT management account\n"
                "  3. Confirm in writing before enrollment\n"
                "  Risk: PPA pricing reverts to standard rates if not transferred"
            )
        },
        {
            "check": "Marketplace Subscriptions",
            "detail": (
                "AWS Marketplace subscriptions are account-level and are NOT affected\n"
                "by Control Tower enrollment. They will continue working."
            ),
            "action": "No action required. Marketplace subscriptions are account-level."
        },
    ]
    for m in manuals:
        record("Commercial", m["check"], MANUAL, m["detail"], m["action"])
        emit(m["check"], MANUAL, "Manual verification required — see action in report")


# ─── SECTION 8: SERVICE QUOTAS / LIMITS ──────────────────────────────────────

def chk_service_quotas(sq_client):
    """Check key Service Quotas relevant to CT enrollment."""
    checks = [
        ("config", "AWS Config", "L-7E1379F5",
         "Config Rules per region", 150, 10,
         "CT uses 10–15 managed rules; ensure sufficient headroom."),
        ("cloudformation", "CloudFormation", "L-0485CB21",
         "Stack count per region", 2000, 15,
         "CT creates 3–5 stacks per governed region."),
    ]

    for service_code, service_name, quota_code, quota_name, default_limit, ct_uses, note in checks:
        resp, err = api(sq_client.get_service_quota,
                        ServiceCode=service_code,
                        QuotaCode=quota_code)
        if err:
            # Try list approach
            list_resp, list_err = api(sq_client.list_service_quotas,
                                      ServiceCode=service_code)
            if list_err:
                record("Service Quotas", f"Quota: {quota_name}", WARN,
                       f"Could not retrieve quota for {service_name}: {err}")
                emit(f"Quota: {quota_name}", WARN, str(err))
                continue
            # Find matching
            quota_val = None
            for q in (list_resp or {}).get("Quotas", []):
                if q.get("QuotaCode") == quota_code:
                    quota_val = q.get("Value", default_limit)
                    break
            if quota_val is None:
                quota_val = default_limit
        else:
            quota_val = resp.get("Quota", {}).get("Value", default_limit)

        if quota_val is None:
            quota_val = default_limit

        used_pct_after = ((ct_uses) / quota_val * 100) if quota_val else 100

        if quota_val - ct_uses > (quota_val * 0.2):
            status = PASS
            note_out = f"Current limit: {int(quota_val)}. CT uses ~{ct_uses}. Headroom OK."
        elif quota_val - ct_uses > 0:
            status = WARN
            note_out = f"Current limit: {int(quota_val)}. CT uses ~{ct_uses}. Approaching limit."
        else:
            status = FAIL
            note_out = f"Current limit: {int(quota_val)}. CT needs ~{ct_uses}. INSUFFICIENT."

        record("Service Quotas", f"Quota: {quota_name}", status,
               f"{note_out}\n{note}",
               f"Request increase if needed: AWS Console → Service Quotas → {service_name}")
        emit(f"Quota: {quota_name}", status, note_out)


# ─── SECTION 9: REGION CHECKS ────────────────────────────────────────────────

def chk_regions(session):
    """Check enabled regions vs typical CT governed regions."""
    CT_CORE_REGIONS = [
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "eu-west-1", "eu-west-2", "eu-central-1",
        "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
    ]
    try:
        acct_client = session.client("account", region_name="us-east-1")
        resp, err = api(acct_client.list_regions,
                        RegionOptStatusContains=["ENABLED", "ENABLED_BY_DEFAULT"])
        if err:
            record("Regions", "Enabled Regions", WARN,
                   f"Could not list regions: {err}",
                   "Manually verify all CT-governed regions are enabled:\n"
                   "  AWS Console → Account Settings → Regions")
            emit("Enabled Regions", WARN, f"Cannot enumerate regions: {err}")
            return

        enabled = {r["RegionName"] for r in resp.get("Regions", [])}
        missing = [r for r in CT_CORE_REGIONS if r not in enabled]

        if not missing:
            record("Regions", "Enabled Regions", PASS,
                   f"All typical CT regions enabled.\nEnabled: {', '.join(sorted(enabled))}")
            emit("Enabled Regions", PASS,
                 f"{len(enabled)} regions enabled — all CT core regions present")
        else:
            record("Regions", "Enabled Regions", WARN,
                   f"Missing CT core regions: {', '.join(missing)}\n"
                   f"Enabled: {', '.join(sorted(enabled))}",
                   "Enable missing regions BEFORE enrollment if CT governs them:\n"
                   "  AWS Console → Account Settings → Regions → Enable\n"
                   f"Missing: {', '.join(missing)}")
            emit("Enabled Regions", WARN,
                 f"Missing {len(missing)} CT core regions: {', '.join(missing)}")
    except Exception as e:
        record("Regions", "Enabled Regions", WARN,
               f"Account API unavailable: {e}",
               "Manually verify all CT-governed regions are enabled.")
        emit("Enabled Regions", WARN, f"Account API unavailable: {e}")


# ─── SECTION 10: SSO / IDENTITY CENTER CHECK ─────────────────────────────────

def chk_sso_readiness(session, region: str):
    """Check if IAM Identity Center is accessible from this account."""
    try:
        sso_client = session.client("sso-admin", region_name=region)
        resp, err = api(sso_client.list_instances)
        if err:
            if "AccessDenied" in str(err):
                record("SSO / Identity Center", "IAM Identity Center Access", INFO,
                       "SSO-Admin API not accessible from this member account (expected).\n"
                       "IAM Identity Center is managed from the management account.",
                       "Ensure the CT management account has IAM Identity Center enabled.\n"
                       "Management account admin must verify: SSO is active and delegated admin configured.")
                emit("IAM Identity Center", INFO,
                     "Not accessible from member account — management account must verify")
            else:
                record("SSO / Identity Center", "IAM Identity Center Access", WARN,
                       f"Unexpected error: {err}")
                emit("IAM Identity Center", WARN, str(err))
            return

        instances = resp.get("Instances", [])
        if instances:
            inst = instances[0]
            record("SSO / Identity Center", "IAM Identity Center", PASS,
                   f"IAM Identity Center instance found:\n"
                   f"  Instance ARN: {inst.get('InstanceArn','?')}\n"
                   f"  Identity Store: {inst.get('IdentityStoreId','?')}")
            emit("IAM Identity Center", PASS,
                 f"Instance found: {inst.get('InstanceArn','?')}")
        else:
            record("SSO / Identity Center", "IAM Identity Center", WARN,
                   "No IAM Identity Center instance found. CT requires SSO/Identity Center.",
                   "Enable IAM Identity Center in the management account before enrollment.")
            emit("IAM Identity Center", WARN, "No instance found — must be enabled in management account")
    except Exception as e:
        record("SSO / Identity Center", "IAM Identity Center Access", INFO,
               f"SSO-Admin not reachable from this account: {e}")
        emit("IAM Identity Center", INFO, "Not reachable from member account (management account must verify)")


# ─── SECTION 11: S3 CHECKS ───────────────────────────────────────────────────

def chk_s3_account_public_access_block(s3control_client, account_id: str):
    """CT guardrail: s3-account-level-public-access-blocks-periodic."""
    resp, err = api(s3control_client.get_public_access_block, AccountId=account_id)
    if err:
        if "NoSuchPublicAccessBlockConfiguration" in str(err):
            record("S3", "Account-Level Public Access Block", FAIL,
                   "No S3 account-level Public Access Block configuration found.\n"
                   "CT detective guardrail 's3-account-level-public-access-blocks' will flag this\n"
                   "account as NON-COMPLIANT immediately after enrollment.",
                   "Enable all four Public Access Block settings before enrollment:\n"
                   "  aws s3control put-public-access-block \\\n"
                   f"    --account-id {account_id} \\\n"
                   "    --public-access-block-configuration \\\n"
                   "      BlockPublicAcls=true,IgnorePublicAcls=true,\\\n"
                   "      BlockPublicPolicy=true,RestrictPublicBuckets=true")
            emit("S3: Account Public Access Block", FAIL,
                 "Not configured — CT guardrail will flag immediately after enrollment")
        else:
            record("S3", "Account-Level Public Access Block", WARN,
                   f"Could not check Public Access Block: {err}",
                   "Manually verify: AWS Console → S3 → Block Public Access (account settings)")
            emit("S3: Account Public Access Block", WARN, str(err))
        return

    cfg = resp.get("PublicAccessBlockConfiguration", {})
    all_blocked = all([
        cfg.get("BlockPublicAcls", False),
        cfg.get("IgnorePublicAcls", False),
        cfg.get("BlockPublicPolicy", False),
        cfg.get("RestrictPublicBuckets", False),
    ])
    missing = [k for k, v in {
        "BlockPublicAcls":      cfg.get("BlockPublicAcls", False),
        "IgnorePublicAcls":     cfg.get("IgnorePublicAcls", False),
        "BlockPublicPolicy":    cfg.get("BlockPublicPolicy", False),
        "RestrictPublicBuckets":cfg.get("RestrictPublicBuckets", False),
    }.items() if not v]

    if all_blocked:
        record("S3", "Account-Level Public Access Block", PASS,
               "All four S3 account-level Public Access Block settings are enabled.")
        emit("S3: Account Public Access Block", PASS, "All 4 settings enabled")
    else:
        record("S3", "Account-Level Public Access Block", WARN,
               f"Partially configured. Missing: {', '.join(missing)}",
               f"Enable missing settings:\n"
               f"  aws s3control put-public-access-block --account-id {account_id} \\\n"
               f"    --public-access-block-configuration "
               f"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true")
        emit("S3: Account Public Access Block", WARN,
             f"Partial — missing: {', '.join(missing)}")


def chk_s3_ct_bucket_names(s3_client, account_id: str):
    """Check if any S3 bucket names collide with CT-reserved bucket naming patterns."""
    resp, err = api(s3_client.list_buckets)
    if err:
        record("S3", "CT Reserved Bucket Name Conflicts", WARN,
               f"Could not list S3 buckets: {err}")
        emit("S3: CT Reserved Bucket Names", WARN, str(err))
        return

    buckets = resp.get("Buckets", [])
    # CT creates buckets with these naming patterns
    ct_patterns = [
        "aws-controltower-logs",
        "aws-controltower-s3-access-logs",
        f"aws-controltower-logs-{account_id}",
        f"aws-controltower-s3-access-logs-{account_id}",
    ]
    conflicts = []
    for b in buckets:
        name = b.get("Name", "")
        for pat in ct_patterns:
            if name.startswith(pat) or name == pat:
                conflicts.append(name)
                break

    if conflicts:
        record("S3", "CT Reserved Bucket Name Conflicts", FAIL,
               f"Found {len(conflicts)} bucket(s) matching CT-reserved naming patterns:\n  " +
               "\n  ".join(conflicts),
               "CT will attempt to create buckets with these names in the Log Archive account.\n"
               "If these buckets exist in this member account with incompatible policies,\n"
               "CT enrollment or logging will fail.\n"
               "Review and rename these buckets if they are not leftover CT artifacts.")
        emit("S3: CT Reserved Bucket Names", FAIL,
             f"{len(conflicts)} CT-reserved bucket name conflicts found")
    else:
        total = len(buckets)
        record("S3", "CT Reserved Bucket Name Conflicts", PASS,
               f"None of the {total} buckets in this account match CT-reserved naming patterns.")
        emit("S3: CT Reserved Bucket Names", PASS,
             f"{total} buckets checked — no CT naming conflicts")


# ─── SECTION 12: EBS ENCRYPTION CHECK ────────────────────────────────────────

def chk_ebs_encryption_default(ec2_client, region: str):
    """CT guardrail: ec2-ebs-encryption-by-default — detects if not enabled."""
    resp, err = api(ec2_client.get_ebs_encryption_by_default)
    if err:
        record("EBS / EC2", f"EBS Encryption By Default [{region}]", WARN,
               f"Could not check EBS encryption default: {err}", region=region)
        emit(f"EBS Encryption Default [{region}]", WARN, str(err))
        return

    enabled = resp.get("EbsEncryptionByDefault", False)
    if enabled:
        record("EBS / EC2", f"EBS Encryption By Default [{region}]", PASS,
               f"EBS encryption by default is ENABLED in {region}.\n"
               "CT detective guardrail will pass.", region=region)
        emit(f"EBS Encryption Default [{region}]", PASS, "Enabled — CT guardrail will pass")
    else:
        record("EBS / EC2", f"EBS Encryption By Default [{region}]", WARN,
               f"EBS encryption by default is DISABLED in {region}.\n"
               "CT detective guardrail 'Detect whether default EBS encryption is enabled' will flag this.",
               f"Enable EBS encryption by default (recommended before enrollment):\n"
               f"  aws ec2 enable-ebs-encryption-by-default --region {region}\n"
               "Note: Existing unencrypted volumes are NOT retroactively encrypted.",
               region=region)
        emit(f"EBS Encryption Default [{region}]", WARN,
             "Disabled — CT detective guardrail will flag this region")


# ─── SECTION 13: GUARDDUTY CHECK ─────────────────────────────────────────────

def chk_guardduty(session, region: str):
    """
    CT integrates with GuardDuty. A pre-existing GuardDuty delegated admin
    in a DIFFERENT account than the CT audit account can block CT from
    configuring GuardDuty governance.
    """
    gd_client = session.client("guardduty", region_name=region)
    resp, err = api(gd_client.list_detectors)
    if err:
        record("GuardDuty", f"GuardDuty Status [{region}]", WARN,
               f"Could not check GuardDuty: {err}", region=region)
        emit(f"GuardDuty [{region}]", WARN, str(err))
        return

    detectors = resp.get("DetectorIds", [])
    if not detectors:
        record("GuardDuty", f"GuardDuty Status [{region}]", INFO,
               f"No GuardDuty detector in {region}. CT will enable GuardDuty if the guardrail is active.",
               region=region)
        emit(f"GuardDuty [{region}]", INFO, "No detector — CT will configure if guardrail enabled")
        return

    detector_id = detectors[0]
    det_resp, det_err = api(gd_client.get_detector, DetectorId=detector_id)
    status      = det_resp.get("Status", "UNKNOWN") if det_resp else "UNKNOWN"
    finding_pub = det_resp.get("FindingPublishingFrequency", "?") if det_resp else "?"
    svc_role    = det_resp.get("ServiceRole", "?") if det_resp else "?"

    # Check if there is a master/administrator account relationship
    master_resp, _ = api(gd_client.get_administrator_account, DetectorId=detector_id)
    admin_acct = None
    if master_resp:
        admin_info = master_resp.get("Administrator", {})
        rel_status = admin_info.get("RelationshipStatus", "")
        if rel_status == "Enabled":
            admin_acct = admin_info.get("AccountId", "?")

    detail = (
        f"Region       : {region}\n"
        f"Detector ID  : {detector_id}\n"
        f"Status       : {status}\n"
        f"Publishing   : {finding_pub}\n"
        f"Admin Account: {admin_acct if admin_acct else 'None (standalone)'}"
    )

    if admin_acct:
        record("GuardDuty", f"GuardDuty Status [{region}]", WARN,
               detail,
               "This account has an active GuardDuty administrator relationship.\n"
               "Verify the admin account matches the CT Audit account.\n"
               "If it points to a DIFFERENT account, CT's security tooling integration may conflict.\n"
               "Action: Confirm with management account admin which account is the GuardDuty delegated admin.",
               region=region)
        emit(f"GuardDuty [{region}]", WARN,
             f"Has GuardDuty admin relationship → account {admin_acct} — verify this matches CT Audit account")
    else:
        record("GuardDuty", f"GuardDuty Status [{region}]", INFO,
               detail + "\nGuardDuty is standalone (no org admin relationship).\n"
               "CT can configure GuardDuty org integration after enrollment.",
               region=region)
        emit(f"GuardDuty [{region}]", INFO,
             f"Standalone detector (status={status}) — CT can adopt after enrollment")


# ─── SECTION 14: SECURITY HUB CHECK ──────────────────────────────────────────

def chk_securityhub(session, region: str):
    """
    Assess Security Hub state for CT enrollment readiness.

    What CT actually does with Security Hub:
    - CT does NOT reconfigure, disable, or modify existing Security Hub settings
    - CT does NOT delete existing standards, findings, or integrations
    - If the target OU has the Security Hub guardrail enabled, CT will attempt to
      configure ORG-LEVEL aggregation via the CT Audit account as delegated admin
    - If Security Hub is already standalone (no org admin), CT can usually adopt it
    - CONFLICT risk: if a DIFFERENT account is already the Security Hub delegated
      admin (not the CT Audit account), CT org integration will fail or conflict

    Three states:
      1. Not enabled             → INFO  (CT enrollment won't touch SH; SH controls are optional)
      2. Enabled, no org admin   → INFO  (expected state — no conflict, no action needed)
      3. Enabled, has org admin:
           - Matches CT Audit    → INFO  (already correctly configured, no conflict)
           - Different account   → WARN  (delegated admin conflict if CT SH controls enabled on OU)
    """
    sh_client = session.client("securityhub", region_name=region)
    resp, err = api(sh_client.describe_hub)
    if err:
        if "InvalidAccessException" in str(err) or "is not subscribed" in str(err) \
                or "not subscribed" in str(err).lower():
            record("Security Hub", f"Security Hub Status [{region}]", INFO,
                   f"Security Hub is NOT enabled in {region}.\n"
                   "CT enrollment does NOT automatically enable Security Hub.\n"
                   "CT Security Hub controls are OPTIONAL and ELECTIVE — they are NOT\n"
                   "auto-applied during enrollment. If you later enable CT SH controls on\n"
                   "the OU, CT will enable Security Hub at that point. No action needed now.",
                   region=region)
            emit(f"Security Hub [{region}]", INFO,
                 "Not enabled — no action needed; CT enrollment does not auto-enable Security Hub")
        else:
            record("Security Hub", f"Security Hub Status [{region}]", WARN,
                   f"Could not check Security Hub: {err}", region=region)
            emit(f"Security Hub [{region}]", WARN, str(err))
        return

    hub_arn       = resp.get("HubArn", "?")
    auto_enable   = resp.get("AutoEnableControls", False)
    subscribed_at = str(resp.get("SubscribedAt", "?"))[:10]

    # Check for org administrator account relationship
    admin_resp, admin_err = api(sh_client.get_administrator_account)
    admin_acct   = None
    member_status = None
    if admin_resp:
        admin_info    = admin_resp.get("Administrator", {})
        member_status = admin_info.get("MemberStatus", "")
        if member_status == "Enabled":
            admin_acct = admin_info.get("AccountId")

    # Get enabled standards count for context
    std_resp, _ = api(sh_client.get_enabled_standards)
    std_count = len(std_resp.get("StandardsSubscriptions", [])) if std_resp else "unknown"

    detail = (
        f"Region             : {region}\n"
        f"Hub ARN            : {hub_arn}\n"
        f"Subscribed since   : {subscribed_at}\n"
        f"Auto-enable controls: {auto_enable}\n"
        f"Enabled standards  : {std_count}\n"
        f"Org Admin Account  : {admin_acct if admin_acct else 'None (standalone)'}\n"
        f"Member status      : {member_status if member_status else 'N/A'}"
    )

    if admin_acct:
        # Has an org admin relationship — is it the CT Audit account?
        record("Security Hub", f"Security Hub Status [{region}]", WARN,
               detail + "\n\nThis account has a Security Hub administrator relationship.\n"
               "If this admin account IS the CT Audit account → no conflict.\n"
               "If this admin account is DIFFERENT → CT org integration will conflict.",
               "VERIFY the admin account ID matches your CT Audit account:\n"
               f"  Admin account found: {admin_acct}\n"
               "  Expected           : <your CT Audit account ID>\n\n"
               "If they MATCH → no action needed, CT will work with existing org admin.\n"
               "If they DIFFER → you must disassociate from the current admin before\n"
               "  CT enrollment, or CT's Security Hub guardrail will fail:\n"
               "  aws securityhub disassociate-from-administrator-account "
               f"--region {region}",
               region=region)
        emit(f"Security Hub [{region}]", WARN,
             f"Has org admin → account {admin_acct} — verify this IS the CT Audit account")
    else:
        # Standalone — no org admin.
        # This is the EXPECTED state for most accounts being enrolled fresh.
        # CT enrollment itself does NOT touch Security Hub at all.
        # CT SH controls are OPTIONAL and ELECTIVE — they are NOT auto-enabled
        # during enrollment. The OU admin must explicitly enable them later.
        # Therefore: standalone Security Hub = no conflict, no action needed.
        CT_SH_CTRL_DOC = (
            "https://docs.aws.amazon.com/controltower/latest/controlreference/"
            "security-hub-controls.html"
        )
        record("Security Hub", f"Security Hub Status [{region}]", INFO,
               detail + "\n\nSecurity Hub is ENABLED standalone (no org admin) — this is fine.\n"
               "CT enrollment does NOT enable, modify, or reconfigure Security Hub.\n"
               "CT Security Hub controls are OPTIONAL and ELECTIVE — not auto-applied.\n"
               "The OU admin must explicitly enable individual CT SH controls after\n"
               "enrollment via the CT console or EnableControl API.\n\n"
               "No action required before enrollment.",
               "No pre-enrollment action required for Security Hub.\n\n"
               "POST-ENROLLMENT (optional — only if you choose to enable CT SH controls):\n"
               "  Enable individual CT Security Hub controls on the target OU via:\n"
               "    CT Console → Controls → filter by 'Security Hub'\n"
               "    or: aws controltower enable-control --control-identifier <arn>\n"
               f"  Reference: {CT_SH_CTRL_DOC}\n\n"
               "  When you enable CT SH controls, CT will:\n"
               "    - Create 'Service-Managed Standard: AWS Control Tower' in Security Hub\n"
               "    - NOT modify your existing {std_count} standard(s)\n"
               "    - NOT delete existing findings or integrations",
               region=region)
        emit(f"Security Hub [{region}]", INFO,
             f"Enabled standalone ({std_count} standards) — no conflict, no pre-enrollment action needed")


def chk_securityhub_ct_standard_presence(sh_client, region: str):
    """
    Check whether 'Service-Managed Standard: AWS Control Tower' already exists
    in this account's Security Hub.

    WHY THIS IS A PRE-ENROLLMENT SIGNAL:
    This standard can ONLY be created by CT when an administrator explicitly
    enables at least one CT Security Hub control on an OU via CT console or
    the EnableControl API. Its presence in a member account before enrollment
    means one of two things:
      a) This account WAS previously enrolled in CT and had CT SH controls
         enabled — it was then unenrolled or enrollment failed and was not
         cleaned up properly
      b) Someone manually enabled CT SH controls on this account's OU outside
         of a formal enrollment workflow

    In either case, finding this standard pre-enrollment indicates the account
    has PRIOR CT INVOLVEMENT — which aligns with the Config recorder/delivery
    channel and CloudFormation baseline stack artifact findings.

    CONFIRMED ARN format (from AWS docs):
      arn:aws:securityhub:::standards/service-managed-aws-control-tower/v/1.0.0
    Ref: https://docs.aws.amazon.com/securityhub/latest/userguide/service-managed-standard-aws-control-tower.html
    """
    std_resp, err = api(sh_client.get_enabled_standards)
    if err:
        record("Security Hub", f"Security Hub: CT Standard Presence [{region}]", WARN,
               f"Could not check enabled standards: {err}", region=region)
        emit(f"Security Hub CT Standard [{region}]", WARN, str(err))
        return

    standards = std_resp.get("StandardsSubscriptions", []) if std_resp else []

    # The confirmed ARN pattern for the CT service-managed standard
    CT_STD_ARN_PATTERN = "service-managed-aws-control-tower"
    ct_standard = None
    for s in standards:
        if CT_STD_ARN_PATTERN in s.get("StandardsArn", "").lower():
            ct_standard = s
            break

    if ct_standard:
        arn    = ct_standard.get("StandardsArn", "?")
        status = ct_standard.get("StandardsStatus", "?")
        sub_arn = ct_standard.get("StandardsSubscriptionArn", "?")
        record("Security Hub", f"Security Hub: CT Standard Presence [{region}]", WARN,
               f"'Service-Managed Standard: AWS Control Tower' EXISTS in this account.\n"
               f"Region              : {region}\n"
               f"Standards ARN       : {arn}\n"
               f"Subscription ARN    : {sub_arn}\n"
               f"Status              : {status}\n\n"
               "DIAGNOSIS: This standard can only be created by CT when CT Security\n"
               "Hub controls are enabled on an OU. Its presence before enrollment\n"
               "strongly indicates this account had PRIOR CT INVOLVEMENT:\n"
               "  - Previously enrolled and unenrolled without full cleanup, OR\n"
               "  - Had CT SH controls enabled outside of formal enrollment\n\n"
               "This correlates with other prior-enrollment indicators:\n"
               "  Config: aws-controltower-BaselineConfigRecorder\n"
               "  Config: aws-controltower-BaselineConfigDeliveryChannel\n"
               "  CloudFormation: AWSControlTowerBP-* stack artifacts\n"
               "  CloudTrail: aws-controltower-BaselineCloudTrail",
               "This standard is additional evidence of prior CT enrollment.\n"
               "It does NOT directly block re-enrollment, but combined with\n"
               "Config/CloudFormation artifacts it confirms cleanup is needed.\n\n"
               "After Config/CloudFormation artifacts are cleaned up, this standard\n"
               "will be recreated automatically during re-enrollment when CT SH\n"
               "controls are enabled on the OU.\n\n"
               "To verify current CT SH controls on this standard:\n"
               f"  aws securityhub describe-standards-controls \\\n"
               f"    --standards-subscription-arn '{sub_arn}' \\\n"
               f"    --region {region}\n\n"
               "Reference:\n"
               "  https://docs.aws.amazon.com/securityhub/latest/userguide/"
               "service-managed-standard-aws-control-tower.html",
               region=region)
        emit(f"Security Hub CT Standard [{region}]", WARN,
             "CT Service-Managed Standard PRESENT — confirms prior CT enrollment on this account")
    else:
        record("Security Hub", f"Security Hub: CT Standard Presence [{region}]", PASS,
               f"'Service-Managed Standard: AWS Control Tower' does NOT exist in {region}.\n"
               "Expected state for a fresh enrollment — no prior CT SH control enablement.",
               region=region)
        emit(f"Security Hub CT Standard [{region}]", PASS,
             "CT Service-Managed Standard absent — expected for fresh enrollment")


# ─── SECTION 15: SNS & LAMBDA NAME COLLISION CHECKS ─────────────────────────

def chk_sns_ct_topic_conflicts(sns_client, region: str):
    """CT creates specific SNS topics; pre-existing same-named topics block this."""
    CT_SNS_PATTERNS = [
        "aws-controltower-",
        "AWSControlTower",
    ]
    all_topics = []
    next_token = None
    while True:
        kwargs = {}
        if next_token:
            kwargs["NextToken"] = next_token
        resp, err = api(sns_client.list_topics, **kwargs)
        if err:
            record("SNS", f"CT SNS Topic Conflicts [{region}]", WARN,
                   f"Could not list SNS topics: {err}", region=region)
            emit(f"SNS Topic Conflicts [{region}]", WARN, str(err))
            return
        all_topics.extend(resp.get("Topics", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break

    conflicts = []
    for t in all_topics:
        arn = t.get("TopicArn", "")
        topic_name = arn.split(":")[-1]
        if any(topic_name.startswith(p) or p.lower() in topic_name.lower()
               for p in CT_SNS_PATTERNS):
            conflicts.append(f"{topic_name}  ({arn})")

    if conflicts:
        record("SNS", f"CT SNS Topic Conflicts [{region}]", WARN,
               f"Found {len(conflicts)} SNS topic(s) matching CT naming patterns in {region}:\n  " +
               "\n  ".join(conflicts[:10]),
               "These may be from a prior CT enrollment. CT's mandatory SCP blocks modification\n"
               "of CT-created SNS topics. If these are orphaned remnants, they may cause\n"
               "enrollment to fail or behave unexpectedly.\n"
               "Action: If remnants from a failed enrollment, contact AWS Support before deleting.",
               region=region)
        emit(f"SNS Topic Conflicts [{region}]", WARN,
             f"{len(conflicts)} CT-named SNS topics found — verify they are not orphaned remnants")
    else:
        record("SNS", f"CT SNS Topic Conflicts [{region}]", PASS,
               f"No SNS topics matching CT naming patterns found in {region}.",
               region=region)
        emit(f"SNS Topic Conflicts [{region}]", PASS,
             "No CT-named SNS topic conflicts")


def chk_lambda_ct_function_conflicts(lambda_client, region: str):
    """CT creates Lambda functions; pre-existing same-named ones block the StackSet deployment."""
    CT_LAMBDA_PATTERNS = [
        "aws-controltower-",
        "AWSControlTower",
    ]
    functions = []
    marker = None
    while True:
        kwargs = {"MaxItems": 50}
        if marker:
            kwargs["Marker"] = marker
        resp, err = api(lambda_client.list_functions, **kwargs)
        if err:
            record("Lambda", f"CT Lambda Function Conflicts [{region}]", WARN,
                   f"Could not list Lambda functions: {err}", region=region)
            emit(f"Lambda Conflicts [{region}]", WARN, str(err))
            return
        functions.extend(resp.get("Functions", []))
        marker = resp.get("NextMarker")
        if not marker:
            break

    conflicts = [
        f.get("FunctionName", "?")
        for f in functions
        if any(f.get("FunctionName", "").startswith(p) or p.lower() in f.get("FunctionName", "").lower()
               for p in CT_LAMBDA_PATTERNS)
    ]

    if conflicts:
        record("Lambda", f"CT Lambda Function Conflicts [{region}]", WARN,
               f"Found {len(conflicts)} Lambda function(s) matching CT naming patterns in {region}:\n  " +
               "\n  ".join(conflicts[:10]),
               "CT's mandatory SCP blocks modification of CT-created Lambda functions.\n"
               "Pre-existing functions with CT-reserved names may conflict with baseline StackSet deployment.\n"
               "If these are orphaned remnants from a prior enrollment, investigate before proceeding.\n"
               "Contact AWS Support if unsure whether to delete.",
               region=region)
        emit(f"Lambda Conflicts [{region}]", WARN,
             f"{len(conflicts)} CT-named Lambda functions found — verify not orphaned remnants")
    else:
        record("Lambda", f"CT Lambda Function Conflicts [{region}]", PASS,
               f"No Lambda functions matching CT naming patterns in {region}.",
               region=region)
        emit(f"Lambda Conflicts [{region}]", PASS,
             "No CT-named Lambda function conflicts")


# ─── SECTION 16: CLOUDWATCH LOG GROUP CONFLICTS ───────────────────────────────

def chk_cloudwatch_ct_log_groups(logs_client, region: str):
    """CT creates specific CloudWatch Log Groups; pre-existing conflicts break the baseline stack."""
    CT_LOG_GROUP_PATTERNS = [
        "aws-controltower/",
        "/aws/controltower/",
        "aws-controltower-BaselineCloudTrail",
    ]
    all_groups = []
    next_token = None
    while True:
        kwargs = {"limit": 50}
        if next_token:
            kwargs["nextToken"] = next_token
        resp, err = api(logs_client.describe_log_groups, **kwargs)
        if err:
            record("CloudWatch Logs", f"CT Log Group Conflicts [{region}]", WARN,
                   f"Could not list log groups: {err}", region=region)
            emit(f"CW Log Group Conflicts [{region}]", WARN, str(err))
            return
        all_groups.extend(resp.get("logGroups", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break

    conflicts = [
        g.get("logGroupName", "?")
        for g in all_groups
        if any(g.get("logGroupName", "").startswith(p) or p in g.get("logGroupName", "")
               for p in CT_LOG_GROUP_PATTERNS)
    ]

    if conflicts:
        record("CloudWatch Logs", f"CT Log Group Conflicts [{region}]", WARN,
               f"Found {len(conflicts)} CloudWatch log group(s) matching CT naming patterns in {region}:\n  " +
               "\n  ".join(conflicts[:10]),
               "CT's baseline CloudFormation stack creates specific log groups.\n"
               "Pre-existing log groups with the same names may cause the baseline stack to fail.\n"
               "These usually indicate a prior CT enrollment attempt.\n"
               "Action: Investigate whether these are orphaned. If so, deleting and re-creating\n"
               "        via enrollment is the correct path. Contact AWS Support if unsure.",
               region=region)
        emit(f"CW Log Group Conflicts [{region}]", WARN,
             f"{len(conflicts)} CT-named log groups found — may indicate prior enrollment attempt")
    else:
        record("CloudWatch Logs", f"CT Log Group Conflicts [{region}]", PASS,
               f"No CloudWatch log groups matching CT naming patterns in {region}.",
               region=region)
        emit(f"CW Log Group Conflicts [{region}]", PASS,
             "No CT-named log group conflicts")


# ─── SECTION 17: IAM USER ACCESS KEY AGE ─────────────────────────────────────

def chk_iam_access_key_age(iam_client):
    """CT guardrail 'access-keys-rotated' flags keys older than 90 days."""
    resp, err = api(iam_client.list_users)
    if err:
        record("IAM", "IAM User Access Key Age (>90 days)", WARN,
               f"Could not list IAM users: {err}",
               "Manually check: aws iam list-users && aws iam list-access-keys --user-name <user>")
        emit("IAM User Access Key Age", WARN, str(err))
        return

    users   = resp.get("Users", [])
    old_keys = []
    now      = datetime.datetime.now(datetime.timezone.utc)

    for user in users:
        uname = user.get("UserName", "?")
        keys_resp, kerr = api(iam_client.list_access_keys, UserName=uname)
        if kerr:
            continue
        for k in keys_resp.get("AccessKeyMetadata", []):
            if k.get("Status") != "Active":
                continue
            created = k.get("CreateDate")
            if created:
                age_days = (now - created).days
                if age_days > 90:
                    old_keys.append(f"{uname}: key {k.get('AccessKeyId','?')} — {age_days} days old")

    if not old_keys:
        record("IAM", "IAM User Access Key Age (>90 days)", PASS,
               f"Checked {len(users)} IAM users — no active access keys older than 90 days.")
        emit("IAM User Access Key Age", PASS,
             f"{len(users)} users checked — no stale access keys")
    else:
        record("IAM", "IAM User Access Key Age (>90 days)", WARN,
               f"{len(old_keys)} active access key(s) older than 90 days:\n  " +
               "\n  ".join(old_keys[:15]),
               "CT detective guardrail 'access-keys-rotated' will flag these immediately after enrollment.\n"
               "Rotate or delete stale access keys before enrollment:\n"
               "  aws iam update-access-key --user-name <user> --access-key-id <key> --status Inactive\n"
               "  aws iam delete-access-key --user-name <user> --access-key-id <key>")
        emit("IAM User Access Key Age", WARN,
             f"{len(old_keys)} access keys >90 days old — CT guardrail will flag these")


# ─── SECTION 18: KMS KEY POLICY CHECK ────────────────────────────────────────

def chk_kms_ct_compatibility(kms_client, region: str):
    """
    If a customer-managed KMS key is used for CloudTrail or Config and its policy
    explicitly denies CT service principals, enrollment will fail silently.
    We enumerate CMKs used by CloudTrail/Config and check for restrictive key policies.
    """
    # Find CMKs associated with CloudTrail
    ct_client_local = None
    try:
        import boto3 as _b3
        sess = _b3.Session()
        ct_client_local = sess.client("cloudtrail", region_name=region)
    except Exception:
        pass

    kms_keys_to_check = []
    if ct_client_local:
        trails_resp, _ = api(ct_client_local.describe_trails, includeShadowTrails=False)
        if trails_resp:
            for trail in trails_resp.get("trailList", []):
                kms_arn = trail.get("KMSKeyId")
                if kms_arn:
                    kms_keys_to_check.append(("CloudTrail", trail.get("Name", "?"), kms_arn))

    if not kms_keys_to_check:
        record("KMS", f"KMS Key Policy — CT Compatibility [{region}]", INFO,
               f"No customer-managed KMS keys found on CloudTrail trails in {region}.\n"
               "Nothing to check for CT principal denial.",
               region=region)
        emit(f"KMS Key Policy [{region}]", INFO,
             "No CMK-encrypted trails — no KMS policy conflict risk")
        return

    CT_PRINCIPALS = [
        "cloudtrail.amazonaws.com",
        "config.amazonaws.com",
        "controltower.amazonaws.com",
        "aws-controltower",
    ]
    issues = []
    for source, resource_name, key_arn in kms_keys_to_check:
        key_id = key_arn.split("/")[-1]
        pol_resp, pol_err = api(kms_client.get_key_policy, KeyId=key_id, PolicyName="default")
        if pol_err:
            issues.append(f"{source}/{resource_name}: could not read key policy — {pol_err}")
            continue
        try:
            policy = json.loads(pol_resp.get("Policy", "{}"))
        except Exception:
            continue

        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") != "Deny":
                continue
            principals = stmt.get("Principal", {})
            if isinstance(principals, str):
                principals = {"AWS": principals}
            all_principals = []
            for v in principals.values():
                all_principals.extend(v if isinstance(v, list) else [v])
            for p in all_principals:
                if any(ct_p in str(p) for ct_p in CT_PRINCIPALS):
                    issues.append(
                        f"{source}/{resource_name}: Key {key_id} has Deny for principal '{p}'"
                    )

    if issues:
        record("KMS", f"KMS Key Policy — CT Compatibility [{region}]", FAIL,
               f"KMS key policy denies CT service principals in {region}:\n  " +
               "\n  ".join(issues),
               "CT uses CloudTrail/Config service principals to access KMS keys.\n"
               "Explicit Deny statements for these principals will cause CT enrollment to fail.\n"
               "Action: Remove or condition the Deny statements in the KMS key policy\n"
               "        to allow cloudtrail.amazonaws.com and controltower.amazonaws.com.",
               region=region)
        emit(f"KMS Key Policy [{region}]", FAIL,
             f"{len(issues)} KMS key(s) deny CT principals — enrollment will fail")
    else:
        checked = [f"{s}/{r}" for s, r, _ in kms_keys_to_check]
        record("KMS", f"KMS Key Policy — CT Compatibility [{region}]", PASS,
               f"KMS keys checked: {', '.join(checked)}\n"
               "No Deny statements found for CT service principals.",
               region=region)
        emit(f"KMS Key Policy [{region}]", PASS,
             f"{len(kms_keys_to_check)} CMK(s) checked — no CT principal denials found")


# ─── SECTION 19: SERVICE-LINKED ROLE CHECKS ──────────────────────────────────

def chk_service_linked_roles(iam_client):
    """
    CT baseline deployment requires certain service-linked roles to be createable.
    Check for pre-existing SLRs that may conflict, and flag missing ones that CT needs.
    """
    REQUIRED_SLRS = {
        "AWSServiceRoleForConfig":
            "config.amazonaws.com — needed for AWS Config service",
        "AWSServiceRoleForCloudTrail":
            "cloudtrail.amazonaws.com — needed for CloudTrail org trail",
        "AWSServiceRoleForOrganizations":
            "organizations.amazonaws.com — needed for AWS Organizations integration",
        "AWSServiceRoleForSupport":
            "support.amazonaws.com — needed for AWS Support",
        "AWSServiceRoleForTrustedAdvisor":
            "trustedadvisor.amazonaws.com — needed for Trusted Advisor",
    }
    found     = {}
    not_found = {}

    for slr_name, description in REQUIRED_SLRS.items():
        resp, err = api(iam_client.get_role, RoleName=slr_name)
        if resp:
            found[slr_name] = resp["Role"].get("Arn", "?")
        else:
            not_found[slr_name] = description

    detail_lines = []
    if found:
        detail_lines.append(f"Present ({len(found)}):")
        detail_lines.extend([f"  ✔ {n}" for n in found])
    if not_found:
        detail_lines.append(f"\nMissing ({len(not_found)}):")
        detail_lines.extend([f"  ✘ {n}  ({d})" for n, d in not_found.items()])

    if not not_found:
        record("IAM", "Service-Linked Roles for CT", PASS,
               "\n".join(detail_lines) if detail_lines else "All required SLRs present.")
        emit("Service-Linked Roles", PASS,
             f"All {len(REQUIRED_SLRS)} required SLRs present")
    else:
        record("IAM", "Service-Linked Roles for CT", WARN,
               "\n".join(detail_lines),
               "Missing SLRs will be auto-created when the corresponding service is first used.\n"
               "However, if SCPs or permission boundaries block SLR creation, CT enrollment may fail.\n"
               "Pre-create them to be safe:\n" +
               "\n".join([
                   f"  aws iam create-service-linked-role --aws-service-name {d.split('—')[0].strip()}"
                   for d in not_found.values()
               ]))
        emit("Service-Linked Roles", WARN,
             f"{len(not_found)} SLRs missing — may auto-create or may fail if SCP blocks SLR creation")


# ─── SECTION 20: ADDITIONAL SERVICE QUOTAS ───────────────────────────────────

def chk_extended_service_quotas(sq_client, region: str):
    """Check Lambda and SNS quotas that CT needs."""
    extended_checks = [
        ("lambda",  "AWS Lambda",  "L-B99A9384",
         "Function count per region",      1000, 5,
         "CT creates ~3 Lambda functions per governed region."),
        ("sns",     "Amazon SNS",  "L-61103206",
         "Topics per account per region",  100000, 3,
         "CT creates SNS topics for notifications per region."),
        ("iam",     "AWS IAM",     "L-FE177D64",
         "Managed policies per account",   1500, 5,
         "CT creates IAM managed policies during enrollment."),
    ]

    for svc_code, svc_name, quota_code, quota_name, default_lim, ct_uses, note in extended_checks:
        resp, err = api(sq_client.get_service_quota,
                        ServiceCode=svc_code, QuotaCode=quota_code)
        if err:
            # Fallback: use the AWS default limit
            quota_val = default_lim
        else:
            quota_val = resp.get("Quota", {}).get("Value", default_lim) or default_lim

        # Also get current usage where possible via applied quota
        applied_resp, _ = api(sq_client.get_aws_default_service_quota,
                              ServiceCode=svc_code, QuotaCode=quota_code)
        default_val = (applied_resp.get("Quota", {}).get("Value", default_lim)
                       if applied_resp else default_lim)

        headroom = quota_val - ct_uses
        if headroom > quota_val * 0.2:
            status   = PASS
            note_out = f"Limit: {int(quota_val)}. CT uses ~{ct_uses}. Headroom OK."
        elif headroom > 0:
            status   = WARN
            note_out = f"Limit: {int(quota_val)}. CT uses ~{ct_uses}. Low headroom."
        else:
            status   = FAIL
            note_out = f"Limit: {int(quota_val)}. CT needs ~{ct_uses}. Insufficient."

        record("Service Quotas", f"Quota: {quota_name} [{region}]", status,
               f"{note_out}\n{note}",
               f"Request increase if needed: Service Quotas → {svc_name} → {quota_name}",
               region=region)
        emit(f"Quota: {quota_name} [{region}]", status, note_out)


# ─── SECTION 21: ACCOUNT CONTACT COMPLETENESS ────────────────────────────────

def chk_account_contact(session):
    """
    CT Account Factory and enrollment require a valid account contact
    (billing email, phone number, address). Incomplete contacts cause
    silent failures in the Account Factory provisioning workflow.
    """
    try:
        acct_client = session.client("account", region_name="us-east-1")
        resp, err = api(acct_client.get_contact_information)
        if err:
            record("Account", "Account Contact Information", WARN,
                   f"Could not retrieve contact information: {err}\n"
                   "This may be a permissions issue or the account may not have\n"
                   "contact information configured.",
                   "Manually verify: AWS Console → Account → Contact Information\n"
                   "Ensure full name, company, address, phone, and email are populated.\n"
                   "Incomplete contacts can cause Account Factory enrollment to fail silently.")
            emit("Account Contact Info", WARN,
                 f"Could not check: {err}")
            return

        contact = resp.get("ContactInformation", {})
        required_fields = {
            "FullName":     contact.get("FullName", ""),
            "PhoneNumber":  contact.get("PhoneNumber", ""),
            "AddressLine1": contact.get("AddressLine1", ""),
            "City":         contact.get("City", ""),
            "CountryCode":  contact.get("CountryCode", ""),
            "PostalCode":   contact.get("PostalCode", ""),
        }
        missing_fields = [k for k, v in required_fields.items() if not v or not v.strip()]

        if not missing_fields:
            record("Account", "Account Contact Information", PASS,
                   "All required contact fields are populated.\n"
                   f"Name: {contact.get('FullName','?')}  |  Country: {contact.get('CountryCode','?')}")
            emit("Account Contact Info", PASS, "All required fields present")
        else:
            record("Account", "Account Contact Information", WARN,
                   f"Missing or empty contact fields: {', '.join(missing_fields)}",
                   "Complete all contact fields before enrollment:\n"
                   "  AWS Console → Account → Contact Information\n"
                   "  Or: aws account put-contact-information --contact-information ...")
            emit("Account Contact Info", WARN,
                 f"Missing fields: {', '.join(missing_fields)}")
    except Exception as e:
        record("Account", "Account Contact Information", WARN,
               f"Account contact API unavailable: {e}",
               "Manually verify contact information in AWS Console → Account → Contact Information.")
        emit("Account Contact Info", WARN, f"API unavailable: {e}")


# ─── SECTION 22: STACKSETS INSTANCE CHECK ────────────────────────────────────

def chk_stackset_instances(cf_client, region: str):
    """
    CT uses StackSets to deploy baseline stacks. If this account is already
    a target in StackSet instances with conflicting stack names, CT deployment will fail.
    """
    # List stack instances where this account is the target
    # We look for stack instances of CT-named StackSets
    CT_STACKSET_PATTERNS = [
        "AWSControlTowerBP-",
        "aws-controltower-",
    ]

    resp, err = api(cf_client.list_stacks,
                    StackStatusFilter=["CREATE_COMPLETE", "UPDATE_COMPLETE",
                                       "ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
                                       "DELETE_FAILED", "CREATE_FAILED"])
    if err:
        record("CloudFormation", f"StackSet Instance Check [{region}]", WARN,
               f"Could not list stacks for StackSet instance check: {err}", region=region)
        emit(f"StackSet Instance Check [{region}]", WARN, str(err))
        return

    stacks = resp.get("StackSummaries", [])
    # Stacks created by StackSets have a root ID that references the StackSet
    stackset_stacks = [
        s for s in stacks
        if s.get("RootId") and any(
            pat.lower() in (s.get("StackName", "") + s.get("RootId", "")).lower()
            for pat in CT_STACKSET_PATTERNS
        )
    ]

    if stackset_stacks:
        names = [f"{s['StackName']} (status={s['StackStatus']})" for s in stackset_stacks[:10]]
        record("CloudFormation", f"StackSet Instance Check [{region}]", WARN,
               f"Found {len(stackset_stacks)} stack(s) in {region} that appear to be\n"
               "StackSet-deployed instances with CT-related names:\n  " +
               "\n  ".join(names),
               "These may be from a prior CT enrollment. CT re-enrollment may:\n"
               "  a) Try to re-deploy over existing stacks (may succeed if idempotent)\n"
               "  b) Fail if stack states are ROLLBACK_COMPLETE or CREATE_FAILED\n"
               "Action: Delete any ROLLBACK_COMPLETE or CREATE_FAILED stacks before re-enrollment.\n"
               "Contact AWS Support before deleting CREATE_COMPLETE stacks.",
               region=region)
        emit(f"StackSet Instance Check [{region}]", WARN,
             f"{len(stackset_stacks)} CT StackSet-deployed stacks found — investigate state")
    else:
        record("CloudFormation", f"StackSet Instance Check [{region}]", PASS,
               f"No CT-related StackSet instance stacks found in {region}.",
               region=region)
        emit(f"StackSet Instance Check [{region}]", PASS,
             "No CT StackSet instance conflicts found")



# ─── SECTION 23: VPC FLOW LOGS CHECK ─────────────────────────────────────────

def chk_vpc_flow_logs(ec2_client, region: str):
    """CT detective guardrail vpc-flow-logs-enabled flags VPCs without active flow logs."""
    vpcs_resp, err = api(ec2_client.describe_vpcs)
    if err:
        record("Networking", f"VPC Flow Logs [{region}]", WARN,
               f"Could not list VPCs: {err}", region=region)
        emit(f"VPC Flow Logs [{region}]", WARN, str(err))
        return
    vpcs = vpcs_resp.get("Vpcs", [])
    if not vpcs:
        record("Networking", f"VPC Flow Logs [{region}]", INFO,
               f"No VPCs in {region}.", region=region)
        emit(f"VPC Flow Logs [{region}]", INFO, "No VPCs")
        return
    vpc_ids = [v["VpcId"] for v in vpcs]
    fl_resp, fl_err = api(ec2_client.describe_flow_logs,
                          Filters=[{"Name": "resource-id", "Values": vpc_ids}])
    if fl_err:
        record("Networking", f"VPC Flow Logs [{region}]", WARN,
               f"Could not describe flow logs: {fl_err}", region=region)
        emit(f"VPC Flow Logs [{region}]", WARN, str(fl_err))
        return
    vpcs_with_logs = {fl["ResourceId"] for fl in fl_resp.get("FlowLogs", [])
                      if fl.get("FlowLogStatus") == "ACTIVE"}
    missing = [v for v in vpc_ids if v not in vpcs_with_logs]
    if not missing:
        record("Networking", f"VPC Flow Logs [{region}]", PASS,
               f"All {len(vpcs)} VPC(s) have active flow logs in {region}.", region=region)
        emit(f"VPC Flow Logs [{region}]", PASS, f"All {len(vpcs)} VPCs have active flow logs")
    else:
        first = missing[0] if missing else "<vpc-id>"
        record("Networking", f"VPC Flow Logs [{region}]", WARN,
               f"{len(missing)}/{len(vpcs)} VPC(s) in {region} have NO active flow logs:\n  "
               + "\n  ".join(missing[:10]),
               "CT guardrail 'vpc-flow-logs-enabled' will flag these VPCs immediately.\n"
               "Enable flow logs before enrollment:\n"
               f"  aws ec2 create-flow-logs --resource-type VPC \\\n"
               f"    --resource-ids {first} --traffic-type ALL \\\n"
               f"    --log-destination-type cloud-watch-logs \\\n"
               f"    --log-group-name /aws/vpc/flowlogs --region {region}",
               region=region)
        emit(f"VPC Flow Logs [{region}]", WARN,
             f"{len(missing)}/{len(vpcs)} VPCs missing flow logs — CT guardrail will flag")


# ─── SECTION 24: EC2 IMDSv2 CHECK ────────────────────────────────────────────

def chk_ec2_imdsv2(ec2_client, region: str):
    """CT guardrail ec2-imdsv2-check flags instances not requiring IMDSv2."""
    resp, err = api(ec2_client.describe_instances,
                    Filters=[{"Name": "instance-state-name",
                              "Values": ["running", "stopped"]}])
    if err:
        record("EBS / EC2", f"EC2 IMDSv2 Enforcement [{region}]", WARN,
               f"Could not list instances: {err}", region=region)
        emit(f"EC2 IMDSv2 [{region}]", WARN, str(err))
        return
    instances = [i for r in resp.get("Reservations", [])
                 for i in r.get("Instances", [])]
    if not instances:
        record("EBS / EC2", f"EC2 IMDSv2 Enforcement [{region}]", INFO,
               f"No EC2 instances in {region}.", region=region)
        emit(f"EC2 IMDSv2 [{region}]", INFO, "No instances")
        return
    imdsv1 = []
    for inst in instances:
        if inst.get("MetadataOptions", {}).get("HttpTokens", "optional") != "required":
            iid  = inst.get("InstanceId", "?")
            it   = inst.get("InstanceType", "?")
            name = next((t["Value"] for t in inst.get("Tags", [])
                         if t["Key"] == "Name"), "")
            imdsv1.append(f"{iid} ({it})" + (f" [{name}]" if name else ""))
    if not imdsv1:
        record("EBS / EC2", f"EC2 IMDSv2 Enforcement [{region}]", PASS,
               f"All {len(instances)} instance(s) in {region} require IMDSv2.", region=region)
        emit(f"EC2 IMDSv2 [{region}]", PASS, f"All {len(instances)} instances enforce IMDSv2")
    else:
        record("EBS / EC2", f"EC2 IMDSv2 Enforcement [{region}]", WARN,
               f"{len(imdsv1)}/{len(instances)} instances allow IMDSv1 in {region}:\n  "
               + "\n  ".join(imdsv1[:10]),
               "CT guardrail 'ec2-imdsv2-check' will flag these instances.\n"
               "Enforce IMDSv2 before enrollment:\n"
               "  aws ec2 modify-instance-metadata-options \\\n"
               f"    --instance-id <id> --http-tokens required --region {region}",
               region=region)
        emit(f"EC2 IMDSv2 [{region}]", WARN,
             f"{len(imdsv1)}/{len(instances)} instances allow IMDSv1 — CT guardrail will flag")


# ─── SECTION 25: S3 BUCKET ENCRYPTION CHECK ──────────────────────────────────

def chk_s3_bucket_encryption(s3_client, region: str):
    """
    Check every S3 bucket for server-side encryption.

    S3 is a global service — list_buckets returns ALL buckets in the account
    regardless of region. We call this once (for primary_region) and scan all.

    Bucket states after get_bucket_encryption:
      - Has SSE rules           → encrypted (count)
      - NoSuchPublicAccessBlock / SSEConfigNotFound error → unencrypted (flag)
      - AccessDenied            → skipped_denied (flag as WARN — can't confirm)
      - Any other error         → skipped_error (flag as WARN)

    A PASS is only issued when unencrypted=0 AND skipped_denied=0.
    If any bucket was access-denied we cannot claim all buckets are encrypted.
    """
    resp, err = api(s3_client.list_buckets)
    if err:
        record("S3", f"S3 Bucket Encryption [{region}]", WARN,
               f"Could not list buckets: {err}", region=region)
        emit(f"S3 Bucket Encryption [{region}]", WARN, str(err))
        return

    buckets = resp.get("Buckets", [])
    if not buckets:
        record("S3", f"S3 Bucket Encryption [{region}]", INFO,
               "No S3 buckets in this account.", region=region)
        emit(f"S3 Bucket Encryption [{region}]", INFO, "No buckets")
        return

    total         = len(buckets)
    encrypted     = []
    unencrypted   = []
    denied        = []   # access denied — cannot confirm state
    other_errors  = []   # other API errors — cannot confirm state

    for b in buckets:
        bname = b.get("Name", "?")
        enc_resp, enc_err = api(s3_client.get_bucket_encryption, Bucket=bname)

        if enc_err:
            err_str = str(enc_err)
            if "ServerSideEncryptionConfigurationNotFoundError" in err_str:
                # Bucket explicitly has no SSE configuration
                unencrypted.append(bname)
            elif "AccessDenied" in err_str or "403" in err_str:
                # Cannot read encryption config — cannot claim it's encrypted
                denied.append(bname)
            elif "NoSuchBucket" in err_str:
                # Race condition — bucket deleted between list and check
                other_errors.append(f"{bname} (NoSuchBucket — deleted during scan)")
            else:
                other_errors.append(f"{bname} ({err_str[:80]})")
            continue

        rules = (enc_resp.get("ServerSideEncryptionConfiguration", {})
                 .get("Rules", []))
        if rules:
            encrypted.append(bname)
        else:
            # Responded but no rules defined — effectively unencrypted
            unencrypted.append(bname)

    # Build detail
    detail_lines = [
        f"Total buckets    : {total}",
        f"Encrypted        : {len(encrypted)}",
        f"Unencrypted      : {len(unencrypted)}",
        f"Access denied    : {len(denied)}  (cannot confirm state)",
        f"Other errors     : {len(other_errors)}",
    ]
    if unencrypted:
        detail_lines.append(f"\nUnencrypted buckets (first 10):\n  " +
                            "\n  ".join(unencrypted[:10]))
    if denied:
        detail_lines.append(f"\nAccess-denied buckets (cannot verify encryption):\n  " +
                            "\n  ".join(denied[:10]))
    if other_errors:
        detail_lines.append(f"\nBuckets with other errors:\n  " +
                            "\n  ".join(other_errors[:5]))
    detail = "\n".join(detail_lines)

    if not unencrypted and not denied and not other_errors:
        # All buckets confirmed encrypted
        record("S3", f"S3 Bucket Encryption [{region}]", PASS,
               f"All {total} bucket(s) confirmed encrypted with SSE.\n" + detail,
               region=region)
        emit(f"S3 Bucket Encryption [{region}]", PASS,
             f"All {total}/{total} buckets confirmed encrypted")

    elif not unencrypted and (denied or other_errors):
        # No confirmed unencrypted, but some buckets couldn't be checked
        record("S3", f"S3 Bucket Encryption [{region}]", WARN,
               f"{len(encrypted)} confirmed encrypted, {len(denied)} could not be verified "
               f"(access denied).\n\n" + detail,
               f"Manually verify encryption on {len(denied)} access-denied bucket(s):\n"
               f"  aws s3api get-bucket-encryption --bucket <name>\n"
               f"  Run from an IAM role with s3:GetEncryptionConfiguration permission.\n\n"
               f"Denied buckets:\n  " + "\n  ".join(denied[:10]),
               region=region)
        emit(f"S3 Bucket Encryption [{region}]", WARN,
             f"{len(encrypted)}/{total} confirmed encrypted | "
             f"{len(denied)} access-denied (unverified) — CANNOT claim all encrypted")

    else:
        # Unencrypted buckets found
        record("S3", f"S3 Bucket Encryption [{region}]", WARN,
               detail,
               "CT detective guardrail 's3-bucket-server-side-encryption-enabled' will "
               "flag unencrypted buckets immediately after enrollment.\n"
               "Enable default SSE on each unencrypted bucket:\n"
               "  aws s3api put-bucket-encryption --bucket <name> \\\n"
               '    --server-side-encryption-configuration'
               " '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":"
               "{\"SSEAlgorithm\":\"AES256\"}}]}'",
               region=region)
        emit(f"S3 Bucket Encryption [{region}]", WARN,
             f"{len(unencrypted)}/{total} unencrypted | "
             f"{len(denied)} access-denied (unverified) | "
             f"{len(encrypted)} confirmed encrypted")


# ─── SECTION 26: IAM USERS WITHOUT MFA ───────────────────────────────────────

def chk_iam_users_without_mfa(iam_client):
    """CT guardrails iam-user-mfa-enabled and mfa-enabled-for-iam-console flag these."""
    users_resp, err = api(iam_client.list_users)
    if err:
        record("IAM", "IAM Users Without MFA", WARN, f"Could not list users: {err}",
               "Check: aws iam list-users")
        emit("IAM Users Without MFA", WARN, str(err))
        return
    users = users_resp.get("Users", [])
    if not users:
        record("IAM", "IAM Users Without MFA", PASS, "No IAM users.")
        emit("IAM Users Without MFA", PASS, "No IAM users")
        return
    has_mfa = set()
    vmfa_resp, _ = api(iam_client.list_virtual_mfa_devices, AssignmentStatus="Assigned")
    if vmfa_resp:
        for dev in vmfa_resp.get("VirtualMFADevices", []):
            un = dev.get("User", {}).get("UserName")
            if un:
                has_mfa.add(un)
    for user in users:
        un = user.get("UserName", "?")
        if un in has_mfa:
            continue
        hw_resp, _ = api(iam_client.list_mfa_devices, UserName=un)
        if hw_resp and hw_resp.get("MFADevices"):
            has_mfa.add(un)
    no_mfa_console = []
    no_mfa_prog    = []
    for user in users:
        un = user.get("UserName", "?")
        if un in has_mfa:
            continue
        lp_resp, _ = api(iam_client.get_login_profile, UserName=un)
        if lp_resp:
            no_mfa_console.append(un)
        else:
            no_mfa_prog.append(un)
    total = len(no_mfa_console) + len(no_mfa_prog)
    if total == 0:
        record("IAM", "IAM Users Without MFA", PASS,
               f"All {len(users)} user(s) have MFA or no console access.")
        emit("IAM Users Without MFA", PASS,
             f"All {len(users)} users have MFA or no console access")
    else:
        detail = f"Users checked: {len(users)}  |  Without MFA: {total}\n"
        if no_mfa_console:
            detail += "\nConsole users WITHOUT MFA (HIGH RISK — CT FAIL):\n  " + \
                      "\n  ".join(no_mfa_console[:15])
        if no_mfa_prog:
            detail += "\n\nProgrammatic-only users without MFA:\n  " + \
                      "\n  ".join(no_mfa_prog[:10])
        record("IAM", "IAM Users Without MFA", WARN, detail,
               "CT guardrails 'iam-user-mfa-enabled' and 'mfa-enabled-for-iam-console'\n"
               "will flag these immediately after enrollment.\n"
               "Assign MFA: IAM Console -> Users -> <user> -> Security credentials -> Assign MFA")
        emit("IAM Users Without MFA", WARN,
             f"{len(no_mfa_console)} console users without MFA | {len(no_mfa_prog)} programmatic without MFA")


# ─── SECTION 27: PERMISSIONS BOUNDARY COMPATIBILITY ──────────────────────────

def chk_permission_boundaries(iam_client, account_id: str):
    """
    Check for permissions boundary conflicts that would block CT enrollment.

    WHAT ACTUALLY BLOCKS CT:
    ─────────────────────────
    CT bootstraps enrollment by assuming AWSControlTowerExecution (or creating it)
    and running with AdministratorAccess. A permissions boundary can restrict this
    in two ways:

    Risk A — Boundary ATTACHED to AWSControlTowerExecution or OrganizationAccountAccessRole:
      The boundary limits what those roles can do. If it prevents iam:CreateRole
      or other actions CT needs, enrollment fails.
      → Check: role.PermissionsBoundary
      → FAIL if found

    Risk B — SCP with Deny iam:CreateRole unless iam:PermissionsBoundary = X:
      SCPs apply to ALL principals in the account including CT's role.
      If such an SCP exists, CT's iam:CreateRole calls will be denied.
      → We CANNOT read SCPs from a member account (requires management account)
      → Flag as MANUAL

    WHAT DOES NOT BLOCK CT (common false positives):
    ─────────────────────────────────────────────────
    - Allow policies with iam:PermissionsBoundary condition attached to OTHER roles/users:
      These restrict what THOSE identities can do. They have zero effect on CT because
      CT uses its own role (AWSControlTowerExecution) which has its own AdministratorAccess.
      An Allow condition in policy A attached to user B does not restrict principal C.

    - Local customer-managed policies that enforce boundaries on developers:
      These are IDENTITY policies attached to specific users/roles. CT's role bypasses
      them entirely — CT is not the principal those policies are attached to.

    The previous version incorrectly scanned all local managed policies for any
    Allow+iam:PermissionsBoundary condition and flagged them. This produced false
    positives for every account that has developer guardrail policies like
    'iam-restricted-list-read' or role-permission policies — those only restrict
    developers, never CT.
    """
    boundary_on_ct = []

    # Risk A: check boundaries directly attached to CT-used roles
    for rname in ["AWSControlTowerExecution", "OrganizationAccountAccessRole"]:
        resp, err = api(iam_client.get_role, RoleName=rname)
        if not resp:
            continue
        pb = resp["Role"].get("PermissionsBoundary", {})
        if pb:
            pb_arn  = pb.get("PermissionsBoundaryArn", "?")
            pb_type = pb.get("PermissionsBoundaryType", "?")
            # Also get what the boundary policy restricts
            pol_resp, _ = api(iam_client.get_policy, PolicyArn=pb_arn)
            pol_name = pol_resp.get("Policy", {}).get("PolicyName", pb_arn) \
                       if pol_resp else pb_arn
            boundary_on_ct.append(
                f"Role '{rname}' — boundary: {pol_name}\n"
                f"    ARN  : {pb_arn}\n"
                f"    Type : {pb_type}\n"
                f"    Effect: Limits what '{rname}' can do — if it blocks iam:CreateRole\n"
                f"            or other CT bootstrap actions, enrollment will FAIL."
            )

    # Risk B: SCPs — CANNOT be read from member account, flag as manual
    # SCPs are the only other mechanism that could enforce boundary requirements
    # on ALL principals including CT's role. Must be verified from management account.

    # Evaluate
    if not boundary_on_ct:
        record("IAM", "Permissions Boundaries — CT Compatibility", PASS,
               "No permissions boundaries attached to CT bootstrap roles.\n"
               "AWSControlTowerExecution and OrganizationAccountAccessRole\n"
               "have no boundary that could restrict CT enrollment actions.\n\n"
               "Note: SCPs can also enforce boundary requirements but cannot be\n"
               "read from a member account. Verify SCPs from the management account:\n"
               "  aws organizations list-policies-for-target \\\n"
               f"    --target-id {account_id} --filter SERVICE_CONTROL_POLICY")
        emit("Permissions Boundary Check", PASS,
             "No boundaries on CT roles — no boundary conflict detected")
        record("IAM", "Permissions Boundaries — SCP Check (Manual)", MANUAL,
               "SCPs can enforce iam:PermissionsBoundary conditions that would block CT\n"
               "from creating roles during enrollment. SCPs cannot be read from a member\n"
               "account — this requires verification from the management account.",
               "From the MANAGEMENT account, run:\n"
               f"  aws organizations list-policies-for-target \\\n"
               f"    --target-id {account_id} --filter SERVICE_CONTROL_POLICY\n\n"
               "For each SCP, check whether any statement has:\n"
               "  Effect: Deny\n"
               "  Action: iam:CreateRole (or iam:* or *)\n"
               "  Condition: StringNotEquals iam:PermissionsBoundary: <specific-arn>\n\n"
               "If such an SCP exists, CT enrollment will fail unless the SCP\n"
               "has an exemption for CT principals:\n"
               "  StringNotLike aws:PrincipalArn:\n"
               "    arn:aws:iam::*:role/AWSControlTowerExecution")
        emit("Permissions Boundary — SCP Check", MANUAL,
             "Cannot read SCPs from member account — verify from management account")
        return

    # Boundaries found on CT roles — FAIL
    lines = ["Boundaries attached to CT bootstrap roles (BLOCKS enrollment):"]
    lines.extend([f"  {b}" for b in boundary_on_ct])

    record("IAM", "Permissions Boundaries — CT Compatibility", FAIL,
           "\n".join(lines),
           "Remove the permissions boundary from CT bootstrap roles before enrollment.\n"
           "A boundary restricts what the role can do — CT needs unrestricted\n"
           "AdministratorAccess on AWSControlTowerExecution to deploy its baseline.\n\n"
           "Remove the boundary:\n"
           "  aws iam delete-role-permissions-boundary \\\n"
           "    --role-name AWSControlTowerExecution\n\n"
           "Also check OrganizationAccountAccessRole if flagged above:\n"
           "  aws iam delete-role-permissions-boundary \\\n"
           "    --role-name OrganizationAccountAccessRole\n\n"
           "After removal, verify the role has AdministratorAccess:\n"
           "  aws iam list-attached-role-policies \\\n"
           "    --role-name AWSControlTowerExecution")
    emit("Permissions Boundary Check", FAIL,
         f"{len(boundary_on_ct)} CT role(s) have a permissions boundary — BLOCKS enrollment")

    # Still surface the SCP manual check
    record("IAM", "Permissions Boundaries — SCP Check (Manual)", MANUAL,
           "After fixing Role boundaries above, also verify SCPs from management account.",
           "From the MANAGEMENT account:\n"
           f"  aws organizations list-policies-for-target \\\n"
           f"    --target-id {account_id} --filter SERVICE_CONTROL_POLICY\n"
           "Check for Deny iam:CreateRole with iam:PermissionsBoundary condition.")
    emit("Permissions Boundary — SCP Check", MANUAL,
         "Also verify SCPs from management account — cannot be read from here")

# ─── SECTION 28: BUDGET / COST ALERTING ──────────────────────────────────────

def chk_budgets(session, account_id: str):
    """CT does not create budgets. Surface as WARN if none exist — CT adds significant cost."""
    try:
        bclient = session.client("budgets", region_name="us-east-1")
        resp, err = api(bclient.describe_budgets, AccountId=account_id)
        if err:
            record("Cost / Budgets", "AWS Budgets", WARN,
                   f"Could not check budgets: {err}",
                   "Manually check: AWS Console -> Billing -> Budgets\n"
                   "Create a budget with email alerts BEFORE enrollment.")
            emit("AWS Budgets", WARN, f"Could not check: {err}")
            return
        budgets = resp.get("Budgets", [])
        if not budgets:
            record("Cost / Budgets", "AWS Budgets", WARN,
                   "No AWS Budgets configured.\n"
                   "Post-enrollment cost increases from CT services will not trigger alerts.",
                   "Create a monthly cost budget before enrollment:\n"
                   "  AWS Console -> Billing -> Budgets -> Create budget\n"
                   "  Set: limit = current spend + 20%, alert at 80% + 100%\n\n"
                   "Estimated CT cost additions per account/month:\n"
                   "  AWS Config      : $100-$1,500 (depends on resource count)\n"
                   "  CloudTrail      : minimal (management events free on 1 trail)\n"
                   "  Security Hub    : $10-$200\n"
                   "  GuardDuty       : $50-$500")
            emit("AWS Budgets", WARN, "No budgets — cost spikes post-enrollment will be silent")
        else:
            lines = []
            for b in budgets[:5]:
                lim = b.get("BudgetLimit", {})
                lines.append(f"{b.get('BudgetName','?')} ({b.get('BudgetType','?')}) "
                             f"limit: {lim.get('Amount','?')} {lim.get('Unit','')}")
            record("Cost / Budgets", "AWS Budgets", PASS,
                   f"{len(budgets)} budget(s) configured:\n  " + "\n  ".join(lines),
                   "Verify budget limits account for CT cost additions:\n"
                   "  Config ~$100-$1,500/mo, Security Hub ~$10-$200/mo, GuardDuty ~$50-$500/mo")
            emit("AWS Budgets", PASS, f"{len(budgets)} budget(s) active")
    except Exception as e:
        record("Cost / Budgets", "AWS Budgets", WARN,
               f"Budgets API unavailable: {e}",
               "Manually create a budget with alerts before enrollment.")
        emit("AWS Budgets", WARN, f"API unavailable: {e}")


# ─── SECTION 29: AWS BACKUP PLANS ────────────────────────────────────────────

def chk_backup_plans(session, region: str):
    """
    CT elective guardrail 'backup-plan-min-frequency-and-min-retention-check'
    requires daily backup with 35-day retention. Flag accounts without any plan.
    """
    try:
        bclient = session.client("backup", region_name=region)
        resp, err = api(bclient.list_backup_plans)
        if err:
            record("AWS Backup", f"Backup Plans [{region}]", INFO,
                   f"Could not check backup plans: {err}", region=region)
            emit(f"Backup Plans [{region}]", INFO, f"Could not check: {err}")
            return
        plans = resp.get("BackupPlansList", [])
        if not plans:
            record("AWS Backup", f"Backup Plans [{region}]", WARN,
                   f"No backup plans in {region}.\n"
                   "CT elective guardrail 'backup-plan-min-frequency-and-min-retention-check'\n"
                   "will flag this if enabled on the target OU.",
                   "Create a backup plan if the target OU has backup guardrails:\n"
                   "  AWS Console -> AWS Backup -> Backup plans -> Create backup plan\n"
                   "  CT minimum: daily frequency, 35-day retention.",
                   region=region)
            emit(f"Backup Plans [{region}]", WARN, "No backup plans found")
        else:
            plan_lines = [
                f"{p.get('BackupPlanName','?')} (created {str(p.get('CreationDate','?'))[:10]})"
                for p in plans[:5]
            ]
            record("AWS Backup", f"Backup Plans [{region}]", PASS,
                   f"{len(plans)} plan(s) in {region}:\n  " + "\n  ".join(plan_lines),
                   "Verify plans meet CT minimum: daily backup, 35-day retention.",
                   region=region)
            emit(f"Backup Plans [{region}]", PASS, f"{len(plans)} backup plan(s)")
    except Exception as e:
        record("AWS Backup", f"Backup Plans [{region}]", INFO,
               f"Backup API unavailable: {e}", region=region)
        emit(f"Backup Plans [{region}]", INFO, f"API unavailable: {e}")


# ─── SECTION 30: TRUSTED ADVISOR SECURITY CHECKS ─────────────────────────────

def chk_trusted_advisor(support_client):
    """
    Trusted Advisor surfaces issues that CT detective guardrails will also flag.
    Remediating TA findings pre-enrollment means a clean CT compliance posture from day 1.
    Requires Business or Enterprise support plan.
    """
    SECURITY_CHECKS = {
        "1iG5NDGVre": "Security Groups - Specific Ports Unrestricted",
        "HCP4007jGY": "Security Groups - Unrestricted Access",
        "Ith3J5jYDS": "MFA on Root Account",
        "7DAFEmoDos": "EBS Public Snapshots",
        "ePs02jT06w": "RDS Public Snapshots",
        "xSqX82fQu":  "S3 Bucket Permissions",
        "nNauJisYIT": "IAM Usage",
        "DqdJqYeRm5": "IAM Access Key Rotation",
    }
    flagged     = []
    unavailable = False
    for check_id, check_name in SECURITY_CHECKS.items():
        resp, err = api(support_client.describe_trusted_advisor_check_result,
                        checkId=check_id, language="en")
        if err:
            if "SubscriptionRequiredException" in str(err):
                unavailable = True
                break
            continue
        status = resp.get("result", {}).get("status", "ok")
        if status in ("warning", "error"):
            n = len(resp.get("result", {}).get("flaggedResources", []))
            flagged.append(f"{check_name}: {status.upper()} ({n} resource(s))")
    if unavailable:
        record("Trusted Advisor", "TA Security Checks", INFO,
               "Trusted Advisor security checks require Business or Enterprise support.\n"
               "Not available on this account's current support tier.",
               "Upgrade support plan to use Trusted Advisor, or manually review the\n"
               "CT guardrail compliance matrix against this account's configuration.")
        emit("Trusted Advisor", INFO, "Requires Business/Enterprise support — not available")
        return
    if not flagged:
        record("Trusted Advisor", "TA Security Checks", PASS,
               f"All {len(SECURITY_CHECKS)} Trusted Advisor security checks returned GREEN.")
        emit("Trusted Advisor", PASS, "All TA security checks green")
    else:
        record("Trusted Advisor", "TA Security Checks", WARN,
               f"{len(flagged)} check(s) flagged:\n  " + "\n  ".join(flagged),
               "These TA findings will likely appear as CT guardrail non-compliance\n"
               "immediately after enrollment. Fix before enrolling:\n"
               "  AWS Console -> Trusted Advisor -> Security")
        emit("Trusted Advisor", WARN,
             f"{len(flagged)} TA security checks flagged — likely CT guardrail findings too")



def chk_prior_enrollment_diagnosis():
    """
    Synthesise all prior-enrollment signals detected across the run into a
    single consolidated diagnosis. This surfaces the connected picture that
    individual per-check findings can't show in isolation.

    Cross-references:
      - Config recorder/delivery channel CT baseline names
      - CT baseline CloudFormation stacks
      - CT-named IAM roles and their trust account IDs
      - CT-named CloudTrail, SNS, Lambda, CloudWatch log groups
      - AWSControlTowerExecution trust account ID
      - Delivery channel S3 bucket account ID (log archive)
      - SNS topic cross-account ARN (audit account)

    When multiple signals point to the same external account IDs, we can
    identify the prior CT management, audit, and log-archive accounts.
    """
    # Collect all prior-enrollment signals from RESULTS
    prior_signals = []
    ct_account_ids = {}   # role/service -> account_id

    for r in RESULTS:
        check = r.get("check", "")
        detail = r.get("detail", "")
        status = r.get("status", "")

        # Config baseline artifacts
        if "aws-controltower-BaselineConfigRecorder" in check and status == FAIL:
            prior_signals.append("AWS Config: aws-controltower-BaselineConfigRecorder (broken state)")
        if "aws-controltower-BaselineConfigDeliveryChannel" in check and status == FAIL:
            prior_signals.append("AWS Config: aws-controltower-BaselineConfigDeliveryChannel (broken state)")
            # Extract log archive account from S3 bucket name in detail
            import re as _re
            bucket_match = _re.search(r'aws-controltower-logs-(\d{12})', detail)
            if bucket_match:
                ct_account_ids["Log Archive account"] = bucket_match.group(1)
            # Extract audit account from SNS topic ARN in detail
            sns_match = _re.search(r'arn:aws:sns:[^:]+:(\d{12}):aws-controltower', detail)
            if sns_match:
                ct_account_ids["Audit account"] = sns_match.group(1)

        # CloudFormation baseline stacks
        if "CT Baseline Stack Artifacts" in check and status in (WARN, FAIL):
            prior_signals.append("CloudFormation: AWSControlTowerBP-* baseline stacks found")

        # CT-named IAM roles
        if "Control Tower Baseline Role Artifacts" in check and status in (WARN, FAIL):
            prior_signals.append("IAM: aws-controltower-* baseline roles present")
            # Extract audit account from role trust (AdministratorExecutionRole trusts audit)
            import re as _re
            audit_match = _re.search(
                r'aws-controltower-AdministratorExecutionRole.*?(\d{12}):role/aws-controltower-Audit',
                detail.replace("\n", " ").replace("<br>", " ")
            )
            if audit_match:
                ct_account_ids["Audit account"] = audit_match.group(1)

        # AWSControlTowerExecution trust account
        if "AWSControlTowerExecution Role" in check and status == WARN:
            import re as _re
            trust_match = _re.search(r'trusts account[:\s]+(\d{12})', detail)
            if trust_match:
                ct_account_ids["Management account (prior CT)"] = trust_match.group(1)

        # CT-named CloudTrail
        if "aws-controltower-BaselineCloudTrail" in check and status in (WARN, INFO):
            prior_signals.append("CloudTrail: aws-controltower-BaselineCloudTrail exists")
            import re as _re
            # S3 bucket in trail contains log archive account ID
            ct_logs_match = _re.search(r'aws-controltower-logs-(\d{12})', detail)
            if ct_logs_match:
                ct_account_ids["Log Archive account"] = ct_logs_match.group(1)

        # CT-named SNS
        if "CT SNS Topic Conflicts" in check and status == WARN:
            prior_signals.append("SNS: aws-controltower-SecurityNotifications topic exists")

        # CT-named Lambda
        if "CT Lambda Function Conflicts" in check and status == WARN:
            prior_signals.append("Lambda: aws-controltower-NotificationForwarder exists")

        # CT-named CloudWatch log group
        if "CT Log Group Conflicts" in check and status == WARN:
            prior_signals.append("CloudWatch Logs: aws-controltower/CloudTrailLogs log group exists")

    if not prior_signals:
        # No prior enrollment signals found — nothing to synthesise
        return

    # Build the consolidated diagnosis
    signal_count = len(prior_signals)
    acct_lines = []
    for role, acct_id in sorted(ct_account_ids.items()):
        acct_lines.append(f"  {role:35s}: {acct_id}")

    detail = (
        f"PRIOR CT ENROLLMENT DIAGNOSIS\n"
        f"{'─' * 60}\n"
        f"This account shows {signal_count} correlated signal(s) of a PRIOR CT enrollment\n"
        f"that was NOT properly cleaned up. The signals are consistent and\n"
        f"point to the same prior CT landing zone.\n\n"
        f"Signals detected:\n"
        + "\n".join(f"  • {s}" for s in prior_signals)
        + (f"\n\nIdentified prior CT landing zone accounts:\n" + "\n".join(acct_lines)
           if acct_lines else "")
        + f"\n\nWHAT THIS MEANS:\n"
        f"  This is NOT a fresh account. It was previously enrolled in CT\n"
        f"  (or had CT partially deployed) under the landing zone identified above.\n"
        f"  The account was unenrolled or enrollment failed, and baseline artifacts\n"
        f"  were left behind. You CANNOT enroll this account cleanly until these\n"
        f"  artifacts are removed — either via the CT unenrollment procedure or\n"
        f"  with AWS Support assistance.\n\n"
        f"  The 3 FAIL items (Config recorder, delivery channel, root MFA) are your\n"
        f"  mandatory blockers. The WARN items below are the cleanup evidence trail."
    )

    action = (
        "RECOMMENDED REMEDIATION SEQUENCE:\n"
        "  Step 1: Verify prior enrollment in CT console (management account)\n"
        "            CT Console → Accounts → search for account 708123178072\n\n"
        "  Step 2a: If account shows as ENROLLED:\n"
        "            Unenroll it first via CT console → Account → Unenroll\n"
        "            Reference: https://docs.aws.amazon.com/controltower/latest/userguide/unenroll-account.html\n\n"
        "  Step 2b: If account shows as NOT enrolled (orphaned artifacts):\n"
        "            Open AWS Support case: 'CT baseline artifact cleanup before re-enrollment'\n"
        "            Reference prior management account: "
        + ct_account_ids.get("Management account (prior CT)", "<see AWSControlTowerExecution trust>")
        + "\n\n"
        "  Step 3: After cleanup confirmed, re-run this readiness script\n"
        "  Step 4: Enroll the account fresh via CT Account Factory\n\n"
        "  Do NOT attempt enrollment while these baseline artifacts exist."
    )

    record("Diagnosis", "Prior CT Enrollment Detected", WARN, detail, action)
    emit("Prior CT Enrollment Detected", WARN,
         f"{signal_count} correlated signals — account has prior CT artifacts that must be cleaned up")

    # Also print a prominent console banner
    bar = "!" * 72
    print(f"\n{C.BOLD}{C.RED}{bar}")
    print(f"  PRIOR CT ENROLLMENT DIAGNOSIS")
    print(f"{bar}{C.RESET}")
    print(f"  {C.YELLOW}{signal_count} signals detected — this account was previously enrolled in CT{C.RESET}")
    if ct_account_ids:
        print(f"  {C.CYAN}Identified prior CT landing zone accounts:{C.RESET}")
        for role, acct in sorted(ct_account_ids.items()):
            print(f"    {C.DIM}{role:35s}: {acct}{C.RESET}")
    print(f"  {C.RED}Resolve the 3 FAIL items before attempting re-enrollment.{C.RESET}")
    print(f"{C.BOLD}{C.RED}{bar}{C.RESET}\n")


# ═════════════════════════════════════════════════════════════════════════════
# REPORT GENERATION
# ═════════════════════════════════════════════════════════════════════════════

def tally() -> dict:
    counts = {PASS: 0, FAIL: 0, WARN: 0, INFO: 0, SKIP: 0, MANUAL: 0}
    for r in RESULTS:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return counts

def verdict(counts: dict) -> tuple[str, str]:
    if counts[FAIL] == 0 and counts[WARN] == 0 and counts[MANUAL] == 0:
        return "✅  ACCOUNT APPEARS READY FOR ENROLLMENT", "#28a745"
    elif counts[FAIL] == 0:
        return "⚠️  ENROLLMENT POSSIBLE — Resolve warnings & complete manual checks first", "#e6a817"
    else:
        return f"❌  NOT READY — {counts[FAIL]} critical issue(s) must be resolved before enrollment", "#dc3545"

def print_summary(counts: dict):
    v, _ = verdict(counts)
    bar = "═" * 72
    print(f"\n{C.BOLD}{bar}{C.RESET}")
    print(f"{C.BOLD}  ASSESSMENT SUMMARY{C.RESET}")
    print(f"{C.BOLD}{bar}{C.RESET}")
    print(f"  {C.GREEN}PASS   : {counts[PASS]}{C.RESET}")
    print(f"  {C.RED}FAIL   : {counts[FAIL]}{C.RESET}")
    print(f"  {C.YELLOW}WARN   : {counts[WARN]}{C.RESET}")
    print(f"  {C.MAGENTA}MANUAL : {counts[MANUAL]}  (require human verification){C.RESET}")
    print(f"  {C.CYAN}INFO   : {counts[INFO]}{C.RESET}")
    print(f"  {C.BOLD}TOTAL  : {len(RESULTS)}{C.RESET}")

    colour = C.GREEN if counts[FAIL] == 0 and counts[WARN] == 0 else \
             C.YELLOW if counts[FAIL] == 0 else C.RED
    print(f"\n  {C.BOLD}{colour}{v}{C.RESET}")
    print(f"{C.BOLD}{bar}{C.RESET}\n")

    if counts[FAIL] > 0:
        print(f"{C.BOLD}{C.RED}  ── CRITICAL — must fix before enrollment ──{C.RESET}")
        for r in RESULTS:
            if r["status"] == FAIL:
                # check name may already contain [region] — don't add it again
                check_display = r['check']
                reg_tag = f" [{r['region']}]"
                if r["region"] != "global" and reg_tag not in check_display:
                    check_display += reg_tag
                print(f"  {C.RED}✘  {r['category']} → {check_display}{C.RESET}")
                if r["action"]:
                    for line in r["action"].splitlines()[:4]:
                        print(f"       {C.DIM}{line}{C.RESET}")
        print()

    if counts[WARN] > 0:
        print(f"{C.BOLD}{C.YELLOW}  ── WARNINGS — review before enrollment ──{C.RESET}")
        for r in RESULTS:
            if r["status"] == WARN:
                check_display = r['check']
                reg_tag = f" [{r['region']}]"
                if r["region"] != "global" and reg_tag not in check_display:
                    check_display += reg_tag
                print(f"  {C.YELLOW}⚠  {r['category']} → {check_display}{C.RESET}")
        print()

    if counts[MANUAL] > 0:
        print(f"{C.BOLD}{C.MAGENTA}  ── MANUAL CHECKS — cannot be automated ──{C.RESET}")
        for r in RESULTS:
            if r["status"] == MANUAL:
                print(f"  {C.MAGENTA}✋  {r['category']} → {r['check']}{C.RESET}")
        print()

def write_text(account_id: str, regions: list[str]) -> str:
    filename = f"ct_member_readiness_{account_id}_{TIMESTAMP}.txt"
    counts   = tally()
    v, _     = verdict(counts)
    lines    = []

    lines.append("=" * 80)
    lines.append("  AWS CONTROL TOWER — MEMBER ACCOUNT PRE-ENROLLMENT READINESS REPORT")
    lines.append("  Script Version : 3.0")
    lines.append(f"  Account ID     : {account_id}")
    lines.append(f"  Regions Checked: {', '.join(regions)}")
    lines.append(f"  Generated      : {utc_now_str()}")
    lines.append("=" * 80)
    lines.append(f"\n  VERDICT : {v}")
    lines.append(f"  PASS={counts[PASS]}  FAIL={counts[FAIL]}  WARN={counts[WARN]}  "
                 f"MANUAL={counts[MANUAL]}  INFO={counts[INFO]}  TOTAL={len(RESULTS)}")

    lines.append("\n" + chr(9472)*78)
    lines.append("  CATEGORY SUMMARY  (F=FAIL  W=WARN  M=MANUAL)")
    lines.append(chr(9472)*78)
    _ct: dict = {}
    for _r in RESULTS:
        _ct.setdefault(_r["category"], {PASS:0,FAIL:0,WARN:0,MANUAL:0,INFO:0})
        _ct[_r["category"]][_r["status"]] = _ct[_r["category"]].get(_r["status"],0)+1
    for _cat, _cc in _ct.items():
        _badge = "ALL OK" if _cc[FAIL]==0 and _cc[WARN]==0 and _cc[MANUAL]==0 \
                 else f"{_cc[FAIL]}F {_cc[WARN]}W {_cc[MANUAL]}M"
        lines.append(f"  [{_badge:^8}]  {_cat}")

    lines.append("\n" + chr(9472)*78)
    lines.append("  ACTION ITEMS  (FAIL / WARN / MANUAL)")
    lines.append(chr(9472)*78)
    _acts = [_r for _r in RESULTS if _r["status"] in (FAIL, WARN, MANUAL)]
    if _acts:
        for _r in _acts:
            _icon = STATUS_ICON.get(_r["status"],"?")
            _chk  = _r["check"]
            _rtag = f" [{_r['region']}]"
            if _r["region"] != "global" and _rtag not in _chk:
                _chk += _rtag
            lines.append(f"  {_icon} [{_r['status']}] {_r['category']} -- {_chk}")
    else:
        lines.append("  None — account looks ready for enrollment!")

    categories = list(dict.fromkeys(r["category"] for r in RESULTS))
    for cat in categories:
        lines.append(f"\n{'─'*80}")
        lines.append(f"  {cat.upper()}")
        lines.append(f"{'─'*80}")
        for r in RESULTS:
            if r["category"] != cat:
                continue
            icon = STATUS_ICON.get(r["status"], "?")
            reg  = f" [{r['region']}]" if r["region"] != "global" else ""
            lines.append(f"\n  {icon} [{r['status']}] {r['check']}{reg}")
            if r["detail"]:
                for dl in r["detail"].splitlines():
                    lines.append(f"      {dl}")
            if r["action"]:
                lines.append(f"    ▶ ACTION:")
                for al in r["action"].splitlines():
                    lines.append(f"      {al}")

    lines.append(f"\n{'='*80}")
    lines.append("  PRE-ENROLLMENT CHECKLIST")
    lines.append(f"{'='*80}")
    for r in RESULTS:
        if r["status"] in (FAIL, WARN, MANUAL):
            chk = f"[ ] [{r['status']}] {r['category']} — {r['check']}"
            lines.append(chk)
    lines.append(f"\n{'='*80}")
    lines.append("  END OF REPORT")
    lines.append(f"{'='*80}")

    with open(filename, "w") as f:
        f.write("\n".join(strip_ansi(l) for l in lines))

    return filename

def write_html(account_id: str, regions: list[str]) -> str:
    filename = f"ct_member_readiness_{account_id}_{TIMESTAMP}.html"
    counts   = tally()
    v, vcolour = verdict(counts)

    # Build rows
    rows = ""
    categories = list(dict.fromkeys(r["category"] for r in RESULTS))
    for cat in categories:
        cat_results = [r for r in RESULTS if r["category"] == cat]
        cat_fail = sum(1 for r in cat_results if r["status"] == FAIL)
        cat_warn = sum(1 for r in cat_results if r["status"] == WARN)
        cat_badge = (
            f'<span style="background:#dc3545;color:#fff;border-radius:4px;padding:2px 6px;font-size:11px;">{cat_fail} FAIL</span>'
            if cat_fail else
            f'<span style="background:#e6a817;color:#fff;border-radius:4px;padding:2px 6px;font-size:11px;">{cat_warn} WARN</span>'
            if cat_warn else
            '<span style="background:#28a745;color:#fff;border-radius:4px;padding:2px 6px;font-size:11px;">OK</span>'
        )
        rows += (
            f'<tr><td colspan="5" style="background:#1e293b;color:#e2e8f0;'
            f'font-weight:600;padding:10px 16px;font-size:13px;">'
            f'▶ {cat} &nbsp; {cat_badge}</td></tr>\n'
        )
        for r in cat_results:
            bg   = STATUS_HTML_BG.get(r["status"], "#fff")
            bc   = STATUS_HTML_BADGE.get(r["status"], "#666")
            icon = STATUS_ICON.get(r["status"], "?")
            reg  = f'<br><span style="font-size:10px;color:#888;">Region: {r["region"]}</span>' \
                   if r["region"] != "global" else ""
            det  = r["detail"].replace("\n", "<br>").replace(" ", "&nbsp;") if r["detail"] else ""
            act  = (
                f'<div style="margin-top:6px;padding:8px 10px;background:#f1f5f9;'
                f'border-left:3px solid {bc};font-size:12px;">'
                f'<strong>Action:</strong><br>'
                f'{r["action"].replace(chr(10),"<br>").replace(" ","&nbsp;")}</div>'
            ) if r["action"] else ""
            rows += (
                f'<tr style="background:{bg};">'
                f'<td style="color:{bc};font-size:20px;text-align:center;width:36px;">{icon}</td>'
                f'<td style="width:90px;">'
                f'<span style="background:{bc};color:#fff;border-radius:4px;'
                f'padding:3px 8px;font-size:11px;font-weight:600;">{r["status"]}</span>'
                f'</td>'
                f'<td style="font-size:13px;font-weight:500;width:260px;">{r["check"]}{reg}</td>'
                f'<td style="font-size:12px;color:#374151;">{det}</td>'
                f'<td style="font-size:12px;min-width:240px;">{act}</td>'
                f'</tr>\n'
            )

    # Checklist section
    checklist_rows = ""
    for r in RESULTS:
        if r["status"] in (FAIL, WARN, MANUAL):
            bc   = STATUS_HTML_BADGE.get(r["status"], "#666")
            _chk_disp = r['check']
            _rtag2 = f" [{r['region']}]"
            if r['region'] != 'global' and _rtag2 not in _chk_disp:
                _chk_disp += _rtag2
            checklist_rows += (
                f'<tr>'
                f'<td style="width:30px;text-align:center;">'
                f'<input type="checkbox" style="width:16px;height:16px;"></td>'
                f'<td><span style="background:{bc};color:#fff;border-radius:3px;'
                f'padding:1px 6px;font-size:10px;">{r["status"]}</span></td>'
                f'<td style="font-size:13px;padding:6px 8px;">'
                f'{r["category"]} &rarr; {_chk_disp}</td>'
                f'</tr>\n'
            )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CT Member Readiness — {account_id}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0;}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
        background:#f8fafc;color:#1e293b;}}
  .hdr{{background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 60%,#1e40af 100%);
        color:#fff;padding:36px 48px;}}
  .hdr h1{{font-size:22px;font-weight:700;margin-bottom:6px;}}
  .hdr p{{font-size:13px;color:#93c5fd;}}
  .scores{{display:flex;gap:14px;flex-wrap:wrap;padding:24px 48px;}}
  .sc{{background:#fff;border-radius:10px;padding:18px 24px;min-width:110px;
       box-shadow:0 1px 6px rgba(0,0,0,.08);text-align:center;}}
  .sc .n{{font-size:34px;font-weight:700;}}
  .sc .l{{font-size:12px;color:#64748b;margin-top:4px;}}
  .verdict{{margin:0 48px 20px;padding:14px 20px;border-radius:8px;background:#fff;
            border-left:5px solid {vcolour};font-size:16px;font-weight:600;
            color:{vcolour};box-shadow:0 1px 6px rgba(0,0,0,.06);}}
  .section-title{{padding:12px 48px;font-size:14px;font-weight:600;color:#475569;
                  border-bottom:1px solid #e2e8f0;margin-bottom:12px;}}
  .tbl-wrap{{padding:0 48px 32px;}}
  table{{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;
         overflow:hidden;box-shadow:0 1px 8px rgba(0,0,0,.07);}}
  th{{background:#1e293b;color:#e2e8f0;padding:10px 14px;text-align:left;
      font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;}}
  td{{padding:9px 14px;border-bottom:1px solid #f1f5f9;vertical-align:top;}}
  tr:last-child td{{border-bottom:none;}}
  .checklist{{padding:0 48px 48px;}}
  .cl-title{{font-size:16px;font-weight:700;margin-bottom:12px;color:#1e293b;}}
  .cl-table{{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;
             box-shadow:0 1px 8px rgba(0,0,0,.07);overflow:hidden;}}
  .cl-table td{{padding:8px 12px;border-bottom:1px solid #f1f5f9;}}
  .footer{{text-align:center;padding:20px;color:#94a3b8;font-size:11px;}}
  @media print{{.hdr{{-webkit-print-color-adjust:exact;print-color-adjust:exact;}}}}
</style>
</head>
<body>

<div class="hdr">
  <h1>🛡️ AWS Control Tower — Member Account Pre-Enrollment Readiness</h1>
  <p>
    Account ID: <strong>{account_id}</strong> &nbsp;|&nbsp;
    Script <strong>v3.0</strong> &nbsp;|&nbsp;
    Regions: {', '.join(regions)} &nbsp;|&nbsp;
    {utc_now_str()}
  </p>
</div>

<div class="scores">
  <div class="sc"><div class="n" style="color:#28a745;">{counts[PASS]}</div><div class="l">PASS</div></div>
  <div class="sc"><div class="n" style="color:#dc3545;">{counts[FAIL]}</div><div class="l">FAIL</div></div>
  <div class="sc"><div class="n" style="color:#e6a817;">{counts[WARN]}</div><div class="l">WARN</div></div>
  <div class="sc"><div class="n" style="color:#8b5cf6;">{counts[MANUAL]}</div><div class="l">MANUAL</div></div>
  <div class="sc"><div class="n" style="color:#17a2b8;">{counts[INFO]}</div><div class="l">INFO</div></div>
  <div class="sc"><div class="n">{len(RESULTS)}</div><div class="l">TOTAL</div></div>
</div>

<div style="padding:4px 48px 16px;display:flex;gap:10px;flex-wrap:wrap;align-items:center;">
  <span style="font-size:13px;font-weight:600;color:#475569;">Filter by status:</span>
  <button onclick="filterTable('ALL')" style="padding:4px 14px;border-radius:6px;border:1px solid #cbd5e1;cursor:pointer;font-size:12px;background:#1e293b;color:#fff;">All</button>
  <button onclick="filterTable('FAIL')" style="padding:4px 14px;border-radius:6px;border:1px solid #dc3545;cursor:pointer;font-size:12px;background:#fff;color:#dc3545;font-weight:700;">&#10008; FAIL</button>
  <button onclick="filterTable('WARN')" style="padding:4px 14px;border-radius:6px;border:1px solid #e6a817;cursor:pointer;font-size:12px;background:#fff;color:#e6a817;font-weight:700;">&#9888; WARN</button>
  <button onclick="filterTable('MANUAL')" style="padding:4px 14px;border-radius:6px;border:1px solid #8b5cf6;cursor:pointer;font-size:12px;background:#fff;color:#8b5cf6;font-weight:700;">&#9995; MANUAL</button>
  <button onclick="filterTable('PASS')" style="padding:4px 14px;border-radius:6px;border:1px solid #28a745;cursor:pointer;font-size:12px;background:#fff;color:#28a745;font-weight:700;">&#10004; PASS</button>
  <span id="ftlbl" style="font-size:12px;color:#64748b;margin-left:6px;"></span>
</div>

<div class="verdict">{v}</div>

<div class="section-title">DETAILED FINDINGS</div>
<div class="tbl-wrap">
<table>
  <thead>
    <tr>
      <th style="width:36px;"></th>
      <th style="width:90px;">Status</th>
      <th style="width:260px;">Check</th>
      <th>Detail</th>
      <th style="width:300px;">Recommended Action</th>
    </tr>
  </thead>
  <tbody>
    {rows}
  </tbody>
</table>
</div>

<div class="checklist" id="checklist">
  <div class="cl-title">📋 Pre-Enrollment Action Checklist</div>
  <p style="font-size:13px;color:#64748b;margin-bottom:12px;">
    Items requiring attention before enrollment. Print or share with your team.
  </p>
  <table class="cl-table">
    <thead>
      <tr style="background:#f8fafc;">
        <th style="width:36px;padding:8px;"></th>
        <th style="width:90px;padding:8px;font-size:12px;">Priority</th>
        <th style="padding:8px;font-size:12px;">Action Required</th>
      </tr>
    </thead>
    <tbody>
      {checklist_rows if checklist_rows else
       '<tr><td colspan="3" style="padding:16px;text-align:center;color:#28a745;">✔ No blocking actions found</td></tr>'}
    </tbody>
  </table>
</div>

<div class="footer">
  AWS Control Tower Pre-Enrollment Readiness Tool <strong>v3.0</strong> &nbsp;|&nbsp;
  Informational only — validate in non-production first &nbsp;|&nbsp;
  ✋ = Manual required &nbsp;|&nbsp;
  <a href="#checklist" style="color:#94a3b8;text-decoration:underline;">Jump to Checklist ↓</a>
</div>
<script>
function filterTable(status) {{
  var rows = document.querySelectorAll("tbody tr");
  var shown = 0;
  rows.forEach(function(row) {{
    if (row.cells.length === 1) {{ row.style.display=""; return; }}
    if (status === "ALL") {{ row.style.display=""; shown++; return; }}
    var spans = row.querySelectorAll("span");
    var badge = "";
    for (var i=0;i<spans.length;i++) {{
      var t = spans[i].textContent.trim();
      if (["PASS","FAIL","WARN","INFO","MANUAL","SKIP"].indexOf(t)>=0){{badge=t;break;}}
    }}
    if (badge===status){{row.style.display="";shown++;}}
    else {{row.style.display="none";}}
  }});
  var lbl=document.getElementById("ftlbl");
  if(lbl) lbl.textContent = status==="ALL" ? "" : "Showing "+shown+" "+status+" result(s)";
}}
</script>
</body>
</html>
"""
    with open(filename, "w") as f:
        f.write(html)
    return filename


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="AWS Control Tower Member Account Pre-Enrollment Readiness Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Run this script from AWS CloudShell while logged into the MEMBER ACCOUNT
        you want to enroll into Control Tower.

        Examples:
          python3 ct_member_readiness.py
          python3 ct_member_readiness.py --region eu-west-1
          python3 ct_member_readiness.py --regions us-east-1 eu-west-1 ap-southeast-1

        Download the HTML report from CloudShell:
          Actions → Download file → ct_member_readiness_<account>_<ts>.html
        """)
    )
    parser.add_argument("--region",  default="us-east-1",
                        help="Primary region (default: us-east-1)")
    parser.add_argument("--regions", nargs="+",
                        help="Check these regions for Config/CloudTrail/networking. "
                             "Defaults to primary region only.")
    args = parser.parse_args()

    primary_region = args.region
    check_regions  = args.regions if args.regions else [primary_region]
    if primary_region not in check_regions:
        check_regions = [primary_region] + check_regions

    # ── Banner
    print(f"\n{C.BOLD}{C.BLUE}╔{'═'*70}╗")
    print(f"║  AWS Control Tower — Member Account Pre-Enrollment Readiness Tool  ║")
    print(f"║  {utc_now_str()}                                               ║")
    print(f"╚{'═'*70}╝{C.RESET}\n")
    print(f"  {C.DIM}Run this from CloudShell inside the MEMBER account you want to enroll.{C.RESET}")
    print(f"  {C.DIM}Regions to check: {', '.join(check_regions)}{C.RESET}\n")

    session = boto3.Session()
    sts_client = session.client("sts", region_name=primary_region)

    # ──────────────────────────────────────────────────────────────────────
    section("1", "ACCOUNT IDENTITY")
    identity = chk_identity(sts_client)
    if not identity:
        print(f"\n{C.RED}Cannot determine account identity. Aborting.{C.RESET}")
        sys.exit(1)

    account_id = identity["Account"]

    org_client = session.client("organizations", region_name="us-east-1")
    chk_account_in_org(org_client, account_id)

    # ──────────────────────────────────────────────────────────────────────
    section("2", "IAM CHECKS")
    iam_client = session.client("iam", region_name=primary_region)
    chk_ct_execution_role(iam_client)
    chk_org_access_role(iam_client)
    chk_ct_role_artifacts(iam_client)
    chk_trust_inventory(iam_client, account_id)
    chk_root_mfa(iam_client)
    chk_iam_password_policy(iam_client)

    # ──────────────────────────────────────────────────────────────────────
    section("3", "AWS CONFIG (per region)")
    for region in check_regions:
        subsection(f"Config — {region}")
        cfg = session.client("config", region_name=region)
        chk_config_recorder(cfg, region)
        chk_config_delivery_channel(cfg, region)
        chk_config_rules(cfg, region)
        chk_config_cost_estimate(cfg, region)

    # ──────────────────────────────────────────────────────────────────────
    section("4", "CLOUDTRAIL (per region)")
    for region in check_regions:
        subsection(f"CloudTrail — {region}")
        ctrail = session.client("cloudtrail", region_name=region)
        chk_cloudtrail(ctrail, region)

    # ──────────────────────────────────────────────────────────────────────
    section("5", "NETWORKING / SECURITY GROUPS (per region)")
    for region in check_regions:
        subsection(f"Networking — {region}")
        ec2 = session.client("ec2", region_name=region)
        chk_open_security_groups(ec2, region)
        chk_default_vpc(ec2, region)

    # ──────────────────────────────────────────────────────────────────────
    section("6", "CLOUDFORMATION (per region)")
    for region in check_regions:
        subsection(f"CloudFormation — {region}")
        cf = session.client("cloudformation", region_name=region)
        chk_ct_baseline_stack_artifacts(cf, region)
        chk_cloudformation(cf, region)

    # ──────────────────────────────────────────────────────────────────────
    section("7", "SERVICE QUOTAS")
    sq = session.client("service-quotas", region_name=primary_region)
    chk_service_quotas(sq)

    # ──────────────────────────────────────────────────────────────────────
    section("8", "REGIONS ENABLED")
    chk_regions(session)

    # ──────────────────────────────────────────────────────────────────────
    section("9", "SSO / IAM IDENTITY CENTER")
    chk_sso_readiness(session, primary_region)

    # ──────────────────────────────────────────────────────────────────────
    section("10", "COMMERCIAL CHECKS")
    subsection("Reserved Instances & Savings Plans")
    for region in check_regions:
        ec2 = session.client("ec2", region_name=region)
        chk_reserved_instances(ec2, region)
    chk_savings_plans(session, primary_region)

    subsection("Support Plan")
    support = session.client("support", region_name="us-east-1")
    chk_support_plan(support)

    subsection("Manual Commercial Checks (Credits, EDP, PPA)")
    chk_manual_commercial()

    # ──────────────────────────────────────────────────────────────────────
    section("11", "S3 CHECKS")
    s3control = session.client("s3control", region_name=primary_region)
    s3_client = session.client("s3", region_name=primary_region)
    chk_s3_account_public_access_block(s3control, account_id)
    chk_s3_ct_bucket_names(s3_client, account_id)

    # ──────────────────────────────────────────────────────────────────────
    section("12", "EBS ENCRYPTION DEFAULT (per region)")
    for region in check_regions:
        subsection(f"EBS — {region}")
        ec2 = session.client("ec2", region_name=region)
        chk_ebs_encryption_default(ec2, region)

    # ──────────────────────────────────────────────────────────────────────
    section("13", "GUARDDUTY STATUS (per region)")
    for region in check_regions:
        subsection(f"GuardDuty — {region}")
        chk_guardduty(session, region)

    # ──────────────────────────────────────────────────────────────────────
    section("14", "SECURITY HUB STATUS (per region)")
    for region in check_regions:
        subsection(f"Security Hub — {region}")
        chk_securityhub(session, region)
        # Check if CT's service-managed standard already exists — evidence of prior enrollment
        _sh = session.client("securityhub", region_name=region)
        chk_securityhub_ct_standard_presence(_sh, region)


    # ──────────────────────────────────────────────────────────────────────
    section("15", "SNS & LAMBDA NAME CONFLICTS (per region)")
    for region in check_regions:
        subsection(f"SNS/Lambda — {region}")
        sns = session.client("sns", region_name=region)
        lmb = session.client("lambda", region_name=region)
        chk_sns_ct_topic_conflicts(sns, region)
        chk_lambda_ct_function_conflicts(lmb, region)

    # ──────────────────────────────────────────────────────────────────────
    section("16", "CLOUDWATCH LOG GROUP CONFLICTS (per region)")
    for region in check_regions:
        subsection(f"CloudWatch Logs — {region}")
        logs = session.client("logs", region_name=region)
        chk_cloudwatch_ct_log_groups(logs, region)

    # ──────────────────────────────────────────────────────────────────────
    section("17", "IAM USER ACCESS KEY AGE")
    chk_iam_access_key_age(iam_client)

    # ──────────────────────────────────────────────────────────────────────
    section("18", "KMS KEY POLICY COMPATIBILITY (per region)")
    for region in check_regions:
        subsection(f"KMS — {region}")
        kms = session.client("kms", region_name=region)
        chk_kms_ct_compatibility(kms, region)

    # ──────────────────────────────────────────────────────────────────────
    section("19", "SERVICE-LINKED ROLES")
    chk_service_linked_roles(iam_client)

    # ──────────────────────────────────────────────────────────────────────
    section("20", "EXTENDED SERVICE QUOTAS (per region)")
    for region in check_regions:
        subsection(f"Quotas — {region}")
        sq_regional = session.client("service-quotas", region_name=region)
        chk_extended_service_quotas(sq_regional, region)

    # ──────────────────────────────────────────────────────────────────────
    section("21", "ACCOUNT CONTACT COMPLETENESS")
    chk_account_contact(session)

    # ──────────────────────────────────────────────────────────────────────
    section("22", "STACKSET INSTANCE CONFLICTS (per region)")
    for region in check_regions:
        subsection(f"StackSets — {region}")
        cf = session.client("cloudformation", region_name=region)
        chk_stackset_instances(cf, region)

    # ──────────────────────────────────────────────────────────────────────
    # ──────────────────────────────────────────────────────────────────────
    section("23", "VPC FLOW LOGS (per region)")
    for region in check_regions:
        subsection(f"Flow Logs — {region}")
        ec2 = session.client("ec2", region_name=region)
        chk_vpc_flow_logs(ec2, region)

    # ──────────────────────────────────────────────────────────────────────
    section("24", "EC2 IMDSv2 ENFORCEMENT (per region)")
    for region in check_regions:
        subsection(f"IMDSv2 — {region}")
        ec2 = session.client("ec2", region_name=region)
        chk_ec2_imdsv2(ec2, region)

    # ──────────────────────────────────────────────────────────────────────
    section("25", "S3 BUCKET ENCRYPTION (global — all account buckets)")
    # S3 is a global service. list_buckets returns ALL buckets in the account
    # regardless of region. We call this once, not per-region.
    chk_s3_bucket_encryption(s3_client, primary_region)

    # ──────────────────────────────────────────────────────────────────────
    section("26", "IAM USERS WITHOUT MFA")
    chk_iam_users_without_mfa(iam_client)

    # ──────────────────────────────────────────────────────────────────────
    section("27", "PERMISSIONS BOUNDARY COMPATIBILITY")
    chk_permission_boundaries(iam_client, account_id)

    # ──────────────────────────────────────────────────────────────────────
    section("28", "BUDGETS & COST ALERTING")
    chk_budgets(session, account_id)

    # ──────────────────────────────────────────────────────────────────────
    section("29", "AWS BACKUP PLANS (per region)")
    for region in check_regions:
        subsection(f"Backup — {region}")
        chk_backup_plans(session, region)

    # ──────────────────────────────────────────────────────────────────────
    section("30", "TRUSTED ADVISOR SECURITY CHECKS")
    ta_sup = session.client("support", region_name="us-east-1")
    chk_trusted_advisor(ta_sup)

    # ──────────────────────────────────────────────────────────────────────
    # Synthesise prior enrollment signals into one consolidated diagnosis
    chk_prior_enrollment_diagnosis()

    # ──────────────────────────────────────────────────────────────────────
    section("31", "SUMMARY & REPORTS")
    counts = tally()
    print_summary(counts)

    print(f"  {C.BOLD}Saving reports...{C.RESET}")
    txt  = write_text(account_id, check_regions)
    html = write_html(account_id, check_regions)

    print(f"  {C.GREEN}📄 Text : {txt}{C.RESET}")
    print(f"  {C.GREEN}🌐 HTML : {html}{C.RESET}")
    print(f"\n  {C.BOLD}To download from CloudShell:{C.RESET}")
    print(f"  {C.DIM}  Actions (top-right menu) → Download file → paste filename above{C.RESET}\n")
    print(f"  {C.MAGENTA}Note: ✋ MANUAL checks require human verification — no script can automate them.{C.RESET}\n")


if __name__ == "__main__":
    main()
