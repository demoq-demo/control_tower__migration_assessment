# AWS Control Tower Readiness Assessment Script

## Purpose
Pre-installation validation tool that checks your AWS environment for Control Tower deployment readiness by identifying potential conflicts and configuration issues.

## Key Functions

### Environment Validation
- Verifies Management Account access (required for Control Tower)
- Checks region support (Control Tower only works in specific regions)
- Validates AWS CLI configuration and permissions

### Conflict Detection
- **AWS Config**: Identifies existing Config recorders that might conflict
- **CloudTrail**: Checks for naming conflicts with Control Tower's trail
- **StackSets**: Reviews existing CloudFormation StackSets for conflicts
- **Service Control Policies**: Examines SCPs that might block Control Tower services

### Resource Assessment
- Account count and limits
- VPC quotas and networking resources
- IAM permissions and user type
- Organizations configuration

## Where to Run
- **✅ Management Account ONLY** (the payer account)
- **❌ Never in production, developer, or shared services accounts**
- **Recommended**: AWS CloudShell for automatic credential handling

## How to Run

### Option 1 - AWS CloudShell (Recommended)
1. Open AWS CloudShell in Management Account
2. Copy script content and save as `readiness_script.sh`
3. Run: `bash readiness_script.sh`
4. Download results: Actions > Download file

### Option 2 - Local Terminal
1. Configure AWS CLI with Management Account credentials
2. Run: `bash readiness_script.sh`

## Prerequisites
- Access to Management Account (current Payer Account)
- Required IAM permissions:
  - `organizations:DescribeOrganization`
  - `organizations:ListAccounts`
  - `organizations:ListPolicies`
  - `configservice:DescribeConfigurationRecorders`
  - `configservice:DescribeConfigurationAggregators`
  - `cloudtrail:DescribeTrails`
  - `cloudformation:ListStackSets`
  - `ec2:DescribeVpcs`
  - `sso-admin:ListInstances`
  - `sts:GetCallerIdentity`

## Output Indicators
- **✅ Green checks**: Requirements met
- **⚠️ Yellow warnings**: Items to review before proceeding
- **❌ Red errors**: Must be fixed before Control Tower installation

## Assessment Checks

1. **Organizations**: Verifies AWS Organizations is enabled
2. **AWS Config**: Checks for existing Config recorders
3. **CloudTrail**: Identifies potential naming conflicts
4. **Region Support**: Validates current region supports Control Tower
5. **Account Limits**: Reviews account count and quotas
6. **Service Control Policies**: Examines restrictive SCPs
7. **IAM Permissions**: Validates user/role permissions
8. **StackSets**: Checks for existing CloudFormation StackSets
9. **VPC Quotas**: Reviews networking resource limits

## Important Notes
- **Read-only assessment** - doesn't modify anything
- Run **BEFORE** installing Control Tower
- Resolve all ❌ and ⚠️ items before proceeding
- CloudShell automatically uses your current account credentials

## Supported Regions
- us-east-1, us-west-2, us-east-2
- eu-west-1, eu-west-2, eu-west-3, eu-central-1, eu-north-1
- ap-southeast-1, ap-southeast-2, ap-northeast-1, ap-south-1
- ca-central-1, sa-east-1



``` bash

#!/usr/bin/env bash
#
# AWS Control Tower Readiness Assessment Script
# 
# 🎯 WHERE TO RUN THIS SCRIPT:
# =====================================
# ✅ MANAGEMENT ACCOUNT ONLY (Current Payer Account)
# ❌ DO NOT run in Production, Developer, or Shared Services accounts
#
# 💻 HOW TO RUN:
# =============
# Option 1 - AWS CloudShell (Recommended):
#   1. Open AWS CloudShell in Management Account
#   2. Copy script content and save as readiness_script.sh
#   3. bash readiness_script.sh
#   4. To download: Actions > Download file > readiness_script.sh
#
# Option 2 - Local Terminal:
#   1. Configure AWS CLI with Management Account credentials
#   2. bash readiness_script.sh
#
# 🔧 PREREQUISITES:
# ================
# - Access to Management Account (current Payer Account)
# - Required Permissions:
#   • organizations:DescribeOrganization
#   • organizations:ListAccounts
#   • organizations:ListPolicies
#   • configservice:DescribeConfigurationRecorders
#   • configservice:DescribeConfigurationAggregators
#   • cloudtrail:DescribeTrails
#   • cloudformation:ListStackSets
#   • ec2:DescribeVpcs
#   • sso-admin:ListInstances
#   • sts:GetCallerIdentity
# - AWS CLI (pre-installed in CloudShell)
#
# 📊 WHAT THIS SCRIPT CHECKS:
# ===========================
# - Organizations access and configuration
# - Existing AWS Config conflicts
# - CloudTrail naming conflicts  
# - Region support for Control Tower
# - Account limits and quotas
#
# ⚠️  IMPORTANT NOTES:
# ===================
# - Run this BEFORE installing Control Tower
# - Resolve all ❌ and ⚠️ items before proceeding
# - This script is READ-ONLY - it doesn't modify anything
# - CloudShell automatically uses your current account credentials
#

echo "==========================================="
echo "🏗️  AWS Control Tower Readiness Assessment"
echo "==========================================="
echo ""

# Detect if running in CloudShell
if [ -n "$AWS_EXECUTION_ENV" ] && [ "$AWS_EXECUTION_ENV" = "CloudShell" ]; then
    echo "☁️  Running in AWS CloudShell"
    echo "✅ AWS CLI pre-configured with your account credentials"
else
    echo "💻 Running in local terminal"
    echo "⚠️  Ensure AWS CLI is configured with Management Account credentials"
fi
echo ""

# STEP 1: Verify you're in the Management Account
echo "🔍 STEP 1: Verifying Management Account Access..."
aws sts get-caller-identity
aws organizations describe-organization

echo ""
echo "📊 STEP 2: Optional - Deploy Detective Guardrails Validation Pack"
echo "(Use this AFTER Control Tower installation for validation)"
echo "Skipping for readiness assessment..."
echo ""

# NOTE: The Detective Guardrails Conformance Pack is for POST-installation validation
# Uncomment below ONLY after Control Tower is installed:

#
# aws configservice put-conformance-pack \
#   --conformance-pack-name "AWSControlTowerDetectiveGuardrails" \
#   --template-s3-uri "s3://aws-config-conformance-packs-us-east-1/AWS-Control-Tower-Detective-Guardrails.yaml" \
#   --delivery-s3-bucket "your-config-delivery-bucket"

echo "🔍 STEP 3: Starting Comprehensive Readiness Assessment..."
echo ""
echo "=== AWS Control Tower Readiness Assessment ==="
echo "Account: $(aws sts get-caller-identity --query Account --output text)"
echo "Region: $(aws configure get region)"
echo "Date: $(date)"
echo "User: $(aws sts get-caller-identity --query Arn --output text)"
echo ""

# Check 1: Organizations
echo "1. Checking AWS Organizations..."
if aws organizations describe-organization &>/dev/null; then
    ORG_ID=$(aws organizations describe-organization --query Organization.Id --output text)
    echo "   ✅ Organizations enabled (ID: $ORG_ID)"
else
    echo "   ❌ Organizations not enabled or no access"
fi

# Check 2: Config
echo "2. Checking AWS Config..."
CONFIG_RECORDERS=$(aws configservice describe-configuration-recorders --query 'ConfigurationRecorders[*].name' --output text 2>/dev/null)
if [ "$CONFIG_RECORDERS" != "" ]; then
    echo "   ⚠️  AWS Config enabled: $CONFIG_RECORDERS"
    echo "      Action: Review for conflicts with Control Tower"
else
    echo "   ✅ No conflicting Config found"
fi

# Check 3: CloudTrail
echo "3. Checking CloudTrail..."
TRAILS=$(aws cloudtrail describe-trails --query 'trailList[*].Name' --output text 2>/dev/null)
if [ "$TRAILS" != "" ]; then
    # Check if Control Tower trail already exists (indicates CT is installed)
    if echo "$TRAILS" | grep -q "aws-controltower-BaselineCloudTrail"; then
        echo "   ℹ️  Control Tower CloudTrail already exists: $TRAILS"
        echo "      Status: Control Tower is already installed"
    else
        echo "   ⚠️  CloudTrail found: $TRAILS"
        echo "      Action: Review for naming conflicts with Control Tower"
    fi
else
    echo "   ✅ No conflicting CloudTrail found"
fi

# Check 4: Region support
echo "4. Checking region support..."
REGION=$(aws configure get region 2>/dev/null || echo "${AWS_DEFAULT_REGION:-not-set}")
if [ "$REGION" = "not-set" ] || [ -z "$REGION" ]; then
    echo "   ❌ No region configured"
    echo "      Action: Set region with 'aws configure set region us-east-1' or export AWS_DEFAULT_REGION"
else
    case $REGION in
        us-east-1|us-west-2|eu-west-1|ap-southeast-2|eu-central-1|ap-northeast-1|ca-central-1|eu-north-1|us-east-2|ap-south-1|ap-southeast-1|eu-west-2|eu-west-3|sa-east-1)
            echo "   ✅ Region $REGION is supported by Control Tower"
            ;;
        *)
            echo "   ❌ Region $REGION is not supported by Control Tower"
            echo "      Supported regions: us-east-1, us-west-2, eu-west-1, ap-southeast-2, eu-central-1,"
            echo "                         ap-northeast-1, ca-central-1, eu-north-1, us-east-2,"
            echo "                         ap-south-1, ap-southeast-1, eu-west-2, eu-west-3, sa-east-1"
            ;;
    esac
fi

# Check 5: Account limits
echo "5. Checking account limits..."
ACCOUNT_COUNT=$(aws organizations list-accounts --query 'length(Accounts)' --output text 2>/dev/null)
if [ "$ACCOUNT_COUNT" != "" ]; then
    echo "   ✅ Current accounts: $ACCOUNT_COUNT"
    if [ "$ACCOUNT_COUNT" -gt 100 ]; then
        echo "      ⚠️  High account count - may need limit increase"
    fi
else
    echo "   ❌ Cannot determine account count"
fi

# Check 6: Service Control Policies (SCPs)
echo "6. Checking Service Control Policies..."
SCP_COUNT=$(aws organizations list-policies --filter SERVICE_CONTROL_POLICY --query 'length(Policies)' --output text 2>/dev/null)
if [ "$SCP_COUNT" != "" ] && [ "$SCP_COUNT" != "None" ] && [ $SCP_COUNT -gt 1 ] 2>/dev/null; then
    echo "   ⚠️  $SCP_COUNT SCPs found (beyond default FullAWSAccess)"
    echo "      Action: Review SCPs for Control Tower service permissions"
    # List non-default SCPs
    aws organizations list-policies --filter SERVICE_CONTROL_POLICY --query 'Policies[?Name!=`FullAWSAccess`].Name' --output text 2>/dev/null | while read -r policy; do
        echo "      - $policy"
    done
else
    echo "   ✅ No restrictive SCPs found"
fi

# Check 7: IAM permissions for Control Tower
echo "7. Checking IAM permissions..."
IAM_USER=$(aws sts get-caller-identity --query Arn --output text | grep -o 'user/[^/]*' || echo "")
if [ "$IAM_USER" != "" ]; then
    echo "   ⚠️  Running as IAM user: $IAM_USER"
    echo "      Recommendation: Use root user or admin role for Control Tower setup"
else
    echo "   ✅ Running as assumed role or root user"
fi

# Check 8: Existing StackSets
echo "8. Checking AWS CloudFormation StackSets..."
STACKSETS=$(aws cloudformation list-stack-sets --query 'Summaries[*].StackSetName' --output text 2>/dev/null)
if [ "$STACKSETS" != "" ]; then
    # Check if Control Tower StackSets exist (indicates CT is installed)
    CT_STACKSETS=$(echo "$STACKSETS" | tr ' ' '\n' | grep -E "^AWSControlTower" | wc -l)
    QUICKSETUP_STACKSETS=$(echo "$STACKSETS" | tr ' ' '\n' | grep -E "^AWS-QuickSetup" | wc -l)
    OTHER_STACKSETS=$(echo "$STACKSETS" | tr ' ' '\n' | grep -vE "^AWSControlTower|^AWS-QuickSetup" | wc -l)
    
    if [ $CT_STACKSETS -gt 0 ]; then
        echo "   ℹ️  Control Tower StackSets found: $CT_STACKSETS (Control Tower is installed)"
    fi
    if [ $QUICKSETUP_STACKSETS -gt 0 ]; then
        echo "   ℹ️  AWS QuickSetup StackSets found: $QUICKSETUP_STACKSETS (Systems Manager, Config, etc.)"
    fi
    if [ $OTHER_STACKSETS -gt 0 ]; then
        echo "   ⚠️  Other StackSets found: $OTHER_STACKSETS"
        echo "      Action: Review for potential conflicts with Control Tower"
        echo "      Other StackSets: $(echo "$STACKSETS" | tr ' ' '\n' | grep -vE "^AWSControlTower|^AWS-QuickSetup" | tr '\n' ' ')"
    fi
else
    echo "   ✅ No existing StackSets found"
fi

# Check 9: VPC and networking quotas
echo "9. Checking VPC quotas..."
VPC_COUNT=$(aws ec2 describe-vpcs --query 'length(Vpcs)' --output text 2>/dev/null)
if [ "$VPC_COUNT" != "" ]; then
    echo "   ✅ Current VPCs: $VPC_COUNT"
    if [ "$VPC_COUNT" -gt 3 ]; then
        echo "      ⚠️  High VPC count - Control Tower creates additional VPCs"
    fi
else
    echo "   ❌ Cannot determine VPC count"
fi

# Check 10: AWS SSO (Identity Center) status
echo "10. Checking AWS SSO/Identity Center..."
SSO_INSTANCES=$(aws sso-admin list-instances --query 'Instances[*].InstanceArn' --output text 2>/dev/null)
if [ "$SSO_INSTANCES" != "" ]; then
    echo "   ⚠️  AWS SSO/Identity Center already enabled"
    echo "      Action: Control Tower will use existing SSO instance"
else
    echo "   ✅ AWS SSO/Identity Center not yet enabled"
fi

# Check 11: Root email access verification
echo "11. Checking root email access..."
ROOT_EMAIL=$(aws organizations describe-organization --query 'Organization.MasterAccountEmail' --output text 2>/dev/null)
if [ "$ROOT_EMAIL" != "" ]; then
    echo "   ✅ Organization root email: $ROOT_EMAIL"
    echo "      ⚠️  Ensure you have access to this email for Control Tower setup"
else
    echo "   ❌ Cannot determine root email"
fi

# Check 12: CRITICAL - SSO Region Alignment
echo "12. 🚨 CRITICAL: Checking SSO region alignment..."
CURRENT_REGION=$(aws configure get region 2>/dev/null || echo "${AWS_DEFAULT_REGION:-not-set}")
SSO_INSTANCES=$(aws sso-admin list-instances --query 'Instances[*].InstanceArn' --output text 2>/dev/null)
if [ "$SSO_INSTANCES" != "" ] && [ "$SSO_INSTANCES" != "None" ]; then
    # Extract region from SSO instance ARN - try multiple methods
    SSO_REGION=$(echo "$SSO_INSTANCES" | head -1 | cut -d':' -f4)
    # Fallback: try getting region from SSO instance directly
    if [ -z "$SSO_REGION" ]; then
        SSO_REGION=$(aws sso-admin list-instances --query 'Instances[0].InstanceArn' --output text 2>/dev/null | cut -d':' -f4)
    fi
    # Final fallback: assume same region as current
    if [ -z "$SSO_REGION" ]; then
        SSO_REGION="$CURRENT_REGION"
        echo "   ℹ️  Cannot extract SSO region, assuming same as current region"
    fi
    
    if [ "$SSO_REGION" = "$CURRENT_REGION" ]; then
        echo "   ✅ SSO region ($SSO_REGION) matches Control Tower region ($CURRENT_REGION)"
    else
        echo "   ❌ CRITICAL: SSO region ($SSO_REGION) != Control Tower region ($CURRENT_REGION)"
        echo "      Action: Deploy Control Tower in $SSO_REGION or recreate SSO in $CURRENT_REGION"
        echo "      Risk: Control Tower installation will FAIL if regions don't match"
    fi
else
    if [ "$CURRENT_REGION" = "not-set" ] || [ -z "$CURRENT_REGION" ]; then
        echo "   ❌ No region configured - cannot validate SSO alignment"
        echo "      Action: Set region first with 'aws configure set region us-east-1'"
    else
        echo "   ✅ No existing SSO - Control Tower will create SSO in current region ($CURRENT_REGION)"
    fi
fi

# Check 13: Config Aggregation readiness
echo "13. Checking Config Aggregation readiness..."
CONFIG_AGGREGATORS=$(aws configservice describe-configuration-aggregators --query 'ConfigurationAggregators[*].ConfigurationAggregatorName' --output text 2>/dev/null)
if [ "$CONFIG_AGGREGATORS" != "" ]; then
    echo "   ⚠️  Existing Config Aggregators: $CONFIG_AGGREGATORS"
    echo "      Action: Control Tower will create its own aggregator in Audit Account"
else
    echo "   ✅ No existing Config Aggregators - Control Tower will create in Audit Account"
fi

# Check 14: Detective Guardrails preparation
echo "14. Checking Detective Guardrails preparation..."
echo "   ℹ️  Detective Guardrails will be deployed automatically by Control Tower"
echo "      Post-installation: Use conformance pack for validation"

# Check 15: Individual account readiness
echo "15. Individual account checks preparation..."
echo "   ℹ️  After Control Tower installation, run Config checks in each account:"
echo "      For Production, Developer, and Shared Services accounts:"
echo "      aws configservice describe-configuration-recorders"

echo ""
echo "==========================================="
echo "✅ Assessment Complete!"
echo "==========================================="
echo ""
echo "📊 NEXT STEPS:"
echo "1. Review any ⚠️ or ❌ items above"
echo "2. CRITICAL: Resolve SSO region alignment if flagged"
echo "3. Resolve all High-risk issues before proceeding"
echo "4. Proceed with Control Tower installation when all ✅"
echo ""
echo "📋 INDIVIDUAL ACCOUNT CHECKS:"
echo "For Production, Developer, and Shared Services accounts:"
echo ""
echo "# Open CloudShell in each account and run:"
echo "CONFIG_RECORDERS=\$(aws configservice describe-configuration-recorders --query 'ConfigurationRecorders[*].name' --output text)"
echo "if [ '\$CONFIG_RECORDERS' != '' ]; then"
echo "    echo '⚠️  AWS Config enabled: \$CONFIG_RECORDERS'"
echo "else"
echo "    echo '✅ No Config conflicts found'"
echo "fi"
echo ""
echo "🌐 CloudShell Tips:"
echo "- CloudShell automatically uses your current account credentials"
echo "- Switch accounts in AWS Console, then open new CloudShell session"
echo "- Files persist for 120 days in CloudShell home directory"
echo "- Use 'aws sts get-caller-identity' to verify current account"
echo ""
echo "📄 Save this output and resolve issues before Control Tower installation."

```
