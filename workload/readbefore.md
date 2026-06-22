# Control Tower Workload Account Readiness Script

## Purpose

This document explains what each check is intended to validate, and what the script does not validate.

The script is a read-only AWS CLI assessment for a **workload account** that may be enrolled into AWS Control Tower. It is meant to be run **before enrollment** to identify conditions that may conflict with Control Tower landing zone controls, logging, guardrails, or baseline resources.

It does **not** enroll the account, remediate issues, or prove that enrollment will succeed.

## What The Script Does At A High Level

The script:

1. Detects the current AWS account, caller ARN, and configured Region.
2. Verifies basic prerequisites such as AWS CLI access.
3. Runs a series of AWS CLI checks across networking, IAM, logging, encryption, and existing resources.
4. Prints findings as:
   - `✅` informational pass
   - `⚠️` warning / review needed
   - `❌` likely blocking or high-risk issue
5. Prints a summary and suggested next steps.

## Intended Execution Context

Run this only in the **target workload account** that is being evaluated for Control Tower enrollment.

Typical execution options:

- AWS CloudShell in the workload account
- Local shell using workload-account AWS credentials

## Required Tools And Assumptions

The script assumes:

- `aws` CLI is installed and authenticated
- the caller has permission to query the services used in the checks
- `jq` may be present, but the script includes simple text parsing fallback for caller identity

The script does **not** self-validate all permissions ahead of time. If some APIs are denied, individual checks may quietly return incomplete results because most AWS CLI calls redirect errors to `/dev/null`.

## Important Implementation Notes

Engineers should know these points before relying on the output:

- The script is **read-only**. It does not create, update, or delete resources.
- It is primarily a **heuristic readiness check**, not a Control Tower compatibility validator.
- A clean result does **not** guarantee successful enrollment.
- Some warnings are broad and require human review rather than indicating a real conflict.
- The list of Control Tower supported Regions is hardcoded and can become stale.
- The script suppresses most AWS CLI errors, so missing permissions can look like “nothing found.”
- There is an implementation bug in the Load Balancer check:
  - `TOTAL_LBS=$((${ALB:-0} + ${CLBS:-0}))`
  - The variable should likely use `ALBS`, not `ALB`
  - As written, the total may undercount or show only classic load balancers

## Script Flow

### 1. Environment and identity detection

The script first collects:

- AWS account ID
- caller ARN
- configured Region
- whether it is running in CloudShell

This establishes who is running the script and in which account and Region the checks are being executed.

## Check-By-Check Breakdown

### Check 1: Region support

What it checks:

- whether an AWS Region is configured
- whether the configured Region appears in the script’s hardcoded Control Tower supported Region list

Why it matters:

- Control Tower enrollment and governance are Region-sensitive

What it does **not** check:

- whether the hardcoded Region list is current
- whether your landing zone has actually enabled that Region
- whether home Region and governed Region strategy are correct

### Check 2: VPC configuration

What it checks:

- total VPC count
- whether a default VPC exists
- how many non-default VPCs exist

Why it matters:

- existing networking can affect how Control Tower baselines interact with the account

What it does **not** check:

- subnet design
- Transit Gateway attachments
- overlapping CIDRs
- network ACLs
- whether the VPC design violates any specific Control Tower control

### Check 3: AWS Config

What it checks:

- existing configuration recorders
- existing delivery channels

Why it matters:

- Control Tower manages Config in enrolled accounts and existing setups can conflict

What it does **not** check:

- recorder status
- recorder scope correctness
- delivery channel destinations
- whether the current Config setup is compatible with the intended landing zone

### Check 4: CloudTrail

What it checks:

- whether trails already exist
- whether any trail is marked as an organization trail

Why it matters:

- Control Tower establishes logging patterns that may overlap with existing trails

What it does **not** check:

- trail event selectors
- multi-Region status
- data event coverage
- log file validation
- encryption configuration
- whether the trail is actually conflicting

### Check 5: IAM roles for conflicts

What it checks:

- presence of roles prefixed with `AWSControlTower` or `aws-controltower`
- presence of `OrganizationAccountAccessRole`
- presence of `AWSCloudFormationStackSetExecutionRole`

Why it matters:

- existing Control Tower roles may indicate the account is already enrolled or partially prepared

What it does **not** check:

- trust policy correctness
- attached permission policies
- whether role names are legitimate or stale
- whether StackSets are currently functional

### Check 6: CloudFormation stacks

What it checks:

- stacks named like `StackSet-AWSControlTower*`
- count of other completed stacks

Why it matters:

- existing Control Tower StackSet artifacts may indicate prior enrollment or partial deployment

What it does **not** check:

- failed stacks
- stack drift
- resource-level conflicts inside non-Control-Tower stacks
- StackSet instances across Regions

### Check 7: CloudWatch log groups

What it checks:

- log groups under `/aws/controltower`

Why it matters:

- may indicate prior Control Tower-related setup

What it does **not** check:

- retention settings
- encryption
- subscription filters
- whether the log groups are active or stale

### Check 8: Account type assessment

What it checks:

- whether the caller ARN shows `OrganizationAccountAccessRole`
- whether the caller appears to be root

Why it matters:

- enrollment is typically done using the expected organizational access path, not root

What it does **not** check:

- whether the caller has every permission required for enrollment
- whether SCPs block required actions

### Check 9: Security groups

What it checks:

- presence of security groups with `0.0.0.0/0` in inbound rules

Why it matters:

- overly permissive security groups may violate governance expectations

What it does **not** check:

- port specificity
- egress rules
- IPv6 exposure
- whether the open rule is justified
- any actual Control Tower guardrail evaluation

### Check 10: S3 buckets

What it checks:

- total bucket count
- bucket names that might conflict with Control Tower naming conventions

Why it matters:

- naming or policy patterns may need review before enrollment

What it does **not** check:

- public access block configuration
- bucket policies
- encryption
- replication
- ownership controls
- whether a bucket name actually causes a collision

### Check 11: IAM users and policies

What it checks:

- total IAM user count
- whether root access keys are present

Why it matters:

- IAM users and especially root keys are high-risk from a governance perspective

What it does **not** check:

- which users have admin privileges
- access key age
- MFA posture
- password policy
- permission boundaries

Note:

- The script says it reviews for `AdministratorAccess`, but it does not actually enumerate attached user or group policies.

### Check 12: KMS keys

What it checks:

- total KMS key count

Why it matters:

- custom KMS policies can affect service integrations and logging flows

What it does **not** check:

- key policy contents
- key state
- alias mapping
- whether any key blocks Control Tower services

### Check 13: Lambda functions

What it checks:

- total function count
- function names that may overlap with Control Tower naming conventions

Why it matters:

- naming and environment complexity can matter during governance onboarding

What it does **not** check:

- event sources
- IAM execution roles
- VPC attachment
- function policies
- whether functions are impacted by enrollment changes

### Check 14: RDS instances

What it checks:

- total RDS DB instance count

Why it matters:

- database workloads may depend on current networking and logging configuration

What it does **not** check:

- subnet groups
- public accessibility
- encryption
- backups
- IAM auth
- parameter groups

### Check 15: Auto Scaling Groups

What it checks:

- total Auto Scaling Group count

Why it matters:

- compute fleets may depend on existing IAM, networking, or logging assumptions

What it does **not** check:

- launch template configuration
- instance profiles
- lifecycle hooks
- mixed instances policy
- scaling policies

### Check 16: CloudWatch alarms

What it checks:

- total metric alarm count

Why it matters:

- baseline changes during enrollment can create noise or alert churn

What it does **not** check:

- alarm actions
- composite alarms
- dashboards
- whether any alarm is tied to Control Tower-relevant resources

### Check 17: VPC endpoints

What it checks:

- total VPC endpoint count

Why it matters:

- private service connectivity can be sensitive to networking governance changes

What it does **not** check:

- endpoint type
- policies
- route table attachment
- private DNS settings

### Check 18: Route tables

What it checks:

- total route table count
- whether any routes appear custom based on route origin

Why it matters:

- custom routing may affect or complicate account governance patterns

What it does **not** check:

- exact route destinations
- blackhole routes
- TGW or VGW dependencies
- subnet associations

### Check 19: SNS topics

What it checks:

- total SNS topic count
- topic ARNs containing `controltower` or `aws-controltower`

Why it matters:

- naming conflicts or prior Control Tower setup may exist

What it does **not** check:

- subscriptions
- encryption
- topic policies
- cross-account publishing

### Check 20: EBS encryption by default

What it checks:

- whether account-level EBS encryption by default is enabled

Why it matters:

- default encryption is a common baseline expectation

What it does **not** check:

- existing unencrypted volumes
- snapshot encryption posture
- KMS key selection

### Check 21: EC2 instances

What it checks:

- count of running EC2 instances

Why it matters:

- active instances can be sensitive to networking, IAM, and logging changes

What it does **not** check:

- stopped instances
- instance profiles
- SSM connectivity
- public IP exposure
- workload criticality

### Check 22: NAT Gateways

What it checks:

- count of available NAT gateways

Why it matters:

- NAT dependencies are relevant to existing network architecture

What it does **not** check:

- route dependencies
- per-AZ design
- failover posture
- data transfer/cost implications

### Check 23: Internet Gateways

What it checks:

- total Internet Gateway count

Why it matters:

- IGWs indicate external connectivity patterns that should be reviewed

What it does **not** check:

- which VPCs they are attached to
- whether routes actually expose public subnets

### Check 24: Load Balancers

What it checks:

- ALB/NLB count via `elbv2`
- classic ELB count via `elb`
- prints a combined count

Why it matters:

- load balancers often sit in front of production workloads affected by network changes

What it does **not** check:

- listener configuration
- public vs internal exposure
- target groups
- WAF associations
- access logs

Important limitation:

- The total count calculation contains a variable typo and may be wrong.

### Check 25: Systems Manager parameters

What it checks:

- total SSM parameter count
- parameters under `/aws/controltower`

Why it matters:

- existing Control Tower parameter paths may indicate prior setup

What it does **not** check:

- parameter values
- SecureString usage
- KMS backing keys
- application dependency on parameters

### Check 26: Secrets Manager

What it checks:

- total secret count

Why it matters:

- secret access models may depend on IAM and KMS posture

What it does **not** check:

- resource policies
- rotation
- replication
- KMS configuration

### Check 27: Resource limits

What it checks:

- whether VPC count exceeds `3`

Why it matters:

- the script uses this as a simple “environment complexity” signal

What it does **not** check:

- actual AWS service quotas
- subnet, ENI, route table, NAT, or other quota consumption
- whether `3` is a meaningful threshold for your environment

## What The Script Checks Well

The script is useful for:

- quickly confirming the account context
- finding obvious pre-existing Control Tower artifacts
- identifying existing Config and CloudTrail setup
- flagging broad networking complexity
- surfacing some naming and governance red flags

## What The Script Does Not Prove

This script does **not** prove:

- that the account is ready for enrollment
- that Control Tower enrollment will succeed
- that Control Tower guardrails will pass after enrollment
- that networking is compatible with landing zone expectations
- that IAM roles and policies are correctly delegated
- that logging, encryption, or SCP posture is complete
- that workload downtime risk is understood

## Major Gaps Engineers Should Know

The script does not inspect several areas that often matter in real Control Tower onboarding:

- AWS Organizations state and OU placement
- SCP impact analysis
- IAM Identity Center / SSO implications
- service-linked roles
- AWS Config recorder status and delivery health
- CloudTrail destination bucket and KMS policy compatibility
- detective guardrail-specific resource violations
- AWS Security Hub / Config rule conflicts
- regional enablement across all governed Regions
- tag policy / backup policy / AI opt-out / residency governance considerations
- VPC sharing, RAM shares, Transit Gateway, Direct Connect, VPN, Route 53 Resolver, Private Hosted Zones
- Control Tower account factory prerequisites

## Known Accuracy Limitations In The Script

- Most AWS CLI errors are hidden with `2>/dev/null`.
- Missing IAM permissions may look like empty results.
- Some checks equate “resource exists” with “potential conflict,” which is only a starting point.
- Some printed statements claim deeper analysis than the code actually performs.
- The hardcoded Region support list can drift from current AWS service reality.
- The load balancer total is currently miscomputed because of a variable mismatch.

## Recommended Usage Pattern

Use this script as a **first-pass assessment**, then follow with manual validation for:

1. AWS Config ownership and recorder design
2. CloudTrail design and destination controls
3. IAM delegation and Organizations access
4. network architecture dependencies
5. Control Tower enrollment history or partial rollout artifacts
6. production workload blast radius

## Example Engineer Interpretation

If the script reports:

- existing Config
- existing CloudTrail
- existing Control Tower roles or StackSet artifacts
- open security groups
- many active workloads

that does **not** automatically mean “do not enroll.” It means:

- the account is not a greenfield account
- enrollment should be planned with more care
- you should review ownership boundaries and potential conflicts before proceeding

## Suggested Improvements To The Script

If this script is going to be maintained, the next practical improvements would be:

1. fail clearly when required IAM permissions are missing
2. fix the load balancer count bug
3. split findings into `critical`, `warning`, and `informational` arrays
4. emit JSON as well as human-readable text
5. inspect Config recorder status and delivery channel details
6. inspect CloudTrail destinations, encryption, and multi-Region status
7. inspect IAM user admin access and root MFA posture
8. inspect public S3 exposure and block-public-access settings
9. inspect Security Group exposure by port and protocol
10. add an explicit “already enrolled / partially enrolled / likely not enrolled” assessment

## Bottom Line

`workload.sh` is a broad pre-enrollment discovery script for a workload account. It is useful for quickly surfacing obvious Control Tower collision points and operational complexity, but it is not a definitive readiness validator. Engineers should treat it as a triage tool, then perform targeted manual review for the areas that matter to the enrollment plan.
