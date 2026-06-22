
#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   AWS Control Tower — Member Account Pre-Enrollment Readiness Tool         ║
║   Version: 1.0  |  Run this INSIDE the member account (CloudShell)         ║
║                                                                              ║
║   PURPOSE: Self-assessment of a single account BEFORE it is enrolled        ║
║   into Control Tower. No management account access required.                 ║
║                                                                              ║
║   USAGE:                                                                     ║
║     python3 ct_member_readiness.py                                           ║
║     python3 ct_member_readiness.py --region eu-west-1                       ║
║     python3 ct_member_readiness.py --regions us-east-1 eu-west-1 ap-east-1  ║
║                                                                              ║
║   OUTPUTS:                                                                   ║
║     Console  : colour-coded live results                                     ║
║     .txt file: plain-text report (email / support ticket)                   ║
║     .html file: rich browser report for customer handover                   ║
║                                                                              ║
║   PERMISSIONS NEEDED (in this member account):                              ║
║     iam:GetAccountSummary, iam:GetRole, iam:ListRoles                       ║
║     iam:GetAccountPasswordPolicy, iam:ListPolicies                          ║
║     config:DescribeConfigurationRecorders                                   ║
║     config:DescribeDeliveryChannels                                         ║
║     config:DescribeConfigRules                                               ║
║     config:GetDiscoveredResourceCounts                                       ║
║     cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus                    ║
║     cloudtrail:GetEventSelectors                                             ║
║     ec2:DescribeRegions, ec2:DescribeReservedInstances                      ║
║     ec2:DescribeVpcs, ec2:DescribeSecurityGroups                            ║
║     organizations:DescribeAccount (may be denied — handled gracefully)      ║
║     sts:GetCallerIdentity                                                    ║
║     support:DescribeSeverityLevels                                          ║
║     cloudformation:ListStacks                                                ║
║     savingsplans:DescribeSavingsPlans                                        ║
║     account:ListRegions                                                      ║
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

TIMESTAMP = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")

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

    role  = resp["Role"]
    arn   = role.get("Arn", "")
    trust = json.dumps(role.get("AssumeRolePolicyDocument", {}), indent=2)

    # Check if trust policy contains a management account principal
    if "sts:AssumeRole" in trust and ("aws-controltower" in trust.lower() or
                                       "controltower" in trust.lower()):
        record("IAM", "AWSControlTowerExecution Role", WARN,
               f"Role EXISTS with a CT-like trust policy.\nARN: {arn}\n"
               f"Trust snippet:\n{trust[:400]}",
               "This may be leftover from a previous CT attempt.\n"
               "Verify the trust policy principal matches your actual management account.\n"
               "If incorrect: aws iam delete-role --role-name AWSControlTowerExecution")
        emit("AWSControlTowerExecution Role", WARN,
             "Role EXISTS — verify trust policy matches your management account")
    else:
        record("IAM", "AWSControlTowerExecution Role", FAIL,
               f"Role EXISTS with an UNRECOGNISED trust policy.\nARN: {arn}\n"
               f"Trust snippet:\n{trust[:400]}",
               "This role will BLOCK CT enrollment. Delete it:\n"
               "  aws iam delete-role --role-name AWSControlTowerExecution\n"
               "(First detach/delete any attached policies if needed.)")
        emit("AWSControlTowerExecution Role", FAIL,
             "Role EXISTS with wrong trust policy — MUST be deleted before enrollment")

def chk_org_access_role(iam_client):
    found = []
    for rname in ["OrganizationAccountAccessRole", "AWSControlTowerExecution"]:
        resp, err = api(iam_client.get_role, RoleName=rname)
        if resp:
            found.append(rname)

    if found:
        record("IAM", "Cross-Account Access Role", PASS,
               f"Found: {', '.join(found)}\nControl Tower can bootstrap into this account.")
        emit("Cross-Account Access Role", PASS, f"Found: {', '.join(found)}")
    else:
        record("IAM", "Cross-Account Access Role", WARN,
               "Neither OrganizationAccountAccessRole nor AWSControlTowerExecution found.",
               "Control Tower needs a cross-account role to bootstrap enrollment.\n"
               "Ask the management account admin to verify they can reach this account.\n"
               "If needed, create OrganizationAccountAccessRole manually:\n"
               "  Principal: arn:aws:iam::<MGMT_ACCOUNT_ID>:root\n"
               "  Policy: AdministratorAccess")
        emit("Cross-Account Access Role", WARN,
             "No cross-account role found — CT may not be able to bootstrap this account")

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
    resp, err = api(config_client.describe_configuration_recorders)
    if err:
        record("AWS Config", "Configuration Recorder", WARN,
               f"Could not check recorders in {region}: {err}", region=region)
        emit(f"Config Recorder [{region}]", WARN, str(err))
        return False   # unknown state

    recorders = resp.get("ConfigurationRecorders", [])
    if not recorders:
        record("AWS Config", "Configuration Recorder", PASS,
               f"No recorder exists in {region}. CT will create one.",
               region=region)
        emit(f"Config Recorder [{region}]", PASS,
             "No recorder — CT will create one (expected)")
        return True   # no conflict

    # Recorder exists — this WILL conflict
    for rec in recorders:
        name     = rec.get("name", "?")
        role_arn = rec.get("roleARN", "?")
        grp      = rec.get("recordingGroup", {})
        scope    = "ALL_SUPPORTED_RESOURCES" if grp.get("allSupported") else \
                   f"{len(grp.get('resourceTypes',[]))} specific types"

        record("AWS Config", f"Configuration Recorder: '{name}'", FAIL,
               f"Region : {region}\n"
               f"Name   : {name}\n"
               f"Role   : {role_arn}\n"
               f"Scope  : {scope}\n"
               f"⚠ Only ONE recorder allowed per region. CT will FAIL to enroll if this exists.",
               f"Delete before enrollment:\n"
               f"  aws configservice delete-configuration-recorder \\\n"
               f"    --configuration-recorder-name {name} --region {region}\n\n"
               f"Save your Config history first if needed (export snapshots).",
               region=region)
        emit(f"Config Recorder '{name}' [{region}]", FAIL,
             f"CONFLICT — will block CT enrollment. Delete recorder in {region} before proceeding.")
    return False  # conflict found

def chk_config_delivery_channel(config_client, region: str):
    resp, err = api(config_client.describe_delivery_channels)
    if err:
        record("AWS Config", "Delivery Channel", WARN,
               f"Could not check delivery channels in {region}: {err}", region=region)
        emit(f"Config Delivery Channel [{region}]", WARN, str(err))
        return

    channels = resp.get("DeliveryChannels", [])
    if not channels:
        record("AWS Config", "Delivery Channel", PASS,
               f"No delivery channel in {region}. CT will create one.",
               region=region)
        emit(f"Config Delivery Channel [{region}]", PASS,
             "No channel — CT will create one (expected)")
        return

    for ch in channels:
        name   = ch.get("name", "?")
        bucket = ch.get("s3BucketName", "?")
        sns    = ch.get("snsTopicARN", "N/A")
        freq   = ch.get("configSnapshotDeliveryProperties", {}).get("deliveryFrequency", "N/A")

        record("AWS Config", f"Delivery Channel: '{name}'", FAIL,
               f"Region    : {region}\n"
               f"Name      : {name}\n"
               f"S3 Bucket : {bucket}\n"
               f"SNS Topic : {sns}\n"
               f"Frequency : {freq}\n"
               f"⚠ Only ONE delivery channel allowed per region. CT enrollment will FAIL.",
               f"Delete before enrollment:\n"
               f"  aws configservice delete-delivery-channel \\\n"
               f"    --delivery-channel-name {name} --region {region}\n\n"
               f"Important: Preserve any compliance logs in '{bucket}' before deletion.\n"
               f"CT will create a new channel pointing to the central Log Archive account.",
               region=region)
        emit(f"Config Delivery Channel '{name}' [{region}]", FAIL,
             f"CONFLICT — #1 enrollment blocker. Bucket: {bucket}. Must delete.")

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
                reg = f" [{r['region']}]" if r["region"] != "global" else ""
                print(f"  {C.RED}✘  {r['category']} → {r['check']}{reg}{C.RESET}")
                if r["action"]:
                    for line in r["action"].splitlines()[:4]:
                        print(f"       {C.DIM}{line}{C.RESET}")
        print()

    if counts[WARN] > 0:
        print(f"{C.BOLD}{C.YELLOW}  ── WARNINGS — review before enrollment ──{C.RESET}")
        for r in RESULTS:
            if r["status"] == WARN:
                reg = f" [{r['region']}]" if r["region"] != "global" else ""
                print(f"  {C.YELLOW}⚠  {r['category']} → {r['check']}{reg}{C.RESET}")
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
    lines.append(f"  Account  : {account_id}")
    lines.append(f"  Regions  : {', '.join(regions)}")
    lines.append(f"  Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("=" * 80)
    lines.append(f"\n  VERDICT : {v}")
    lines.append(f"  PASS={counts[PASS]}  FAIL={counts[FAIL]}  WARN={counts[WARN]}  "
                 f"MANUAL={counts[MANUAL]}  INFO={counts[INFO]}")

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
            checklist_rows += (
                f'<tr>'
                f'<td style="width:30px;text-align:center;">'
                f'<input type="checkbox" style="width:16px;height:16px;"></td>'
                f'<td><span style="background:{bc};color:#fff;border-radius:3px;'
                f'padding:1px 6px;font-size:10px;">{r["status"]}</span></td>'
                f'<td style="font-size:13px;padding:6px 8px;">'
                f'{r["category"]} &rarr; {r["check"]}</td>'
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
    Regions assessed: {', '.join(regions)} &nbsp;|&nbsp;
    Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
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

<div class="checklist">
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
  AWS Control Tower Pre-Enrollment Readiness Tool &nbsp;|&nbsp;
  This report is informational only. Always validate in a non-production account first. &nbsp;|&nbsp;
  ✋ = Manual verification required
</div>
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
    print(f"║  {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}                                               ║")
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
    section("11", "SUMMARY & REPORTS")
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
