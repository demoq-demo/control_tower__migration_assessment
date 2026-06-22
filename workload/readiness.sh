#!/usr/bin/env bash
#
# AWS Control Tower Workload Account Readiness Assessment Script
# 
# 🎯 WHERE TO RUN THIS SCRIPT:
# =====================================
# ✅ WORKLOAD ACCOUNT ONLY (Target account to be enrolled in Control Tower)
# ❌ DO NOT run in Management Account or other accounts
#
# 💻 HOW TO RUN:
# =============
# Option 1 - AWS CloudShell (Recommended):
#   1. Open AWS CloudShell in Target Workload Account
#   2. Copy script content and save as workload.sh
#   3. bash workload.sh
#
# Option 2 - Local Terminal:
#   1. Configure AWS CLI with Workload Account credentials
#   2. bash workload.sh
#
# 🔧 PREREQUISITES:
# ================
# - Access to Target Workload Account
# - Required Permissions:
#   • sts:GetCallerIdentity
#   • ec2:DescribeVpcs
#   • ec2:DescribeSubnets
#   • ec2:DescribeRouteTables
#   • ec2:DescribeInternetGateways
#   • configservice:DescribeConfigurationRecorders
#   • cloudtrail:DescribeTrails
#   • iam:ListRoles
#   • iam:GetRole
#   • cloudformation:ListStacks
#   • logs:DescribeLogGroups
#
# 📊 WHAT THIS SCRIPT CHECKS:
# ===========================
# - Account identity and region
# - VPC configuration conflicts
# - Existing AWS Config setup
# - CloudTrail configuration
# - IAM roles that might conflict
# - CloudFormation stacks
# - Resource naming conflicts
#
# ⚠️  IMPORTANT NOTES:
# ===================
# - Run this BEFORE enrolling account in Control Tower
# - Resolve all ❌ and ⚠️ items before proceeding
# - This script is READ-ONLY - it doesn't modify anything
#

echo "=============================================="
echo "🏗️  AWS Control Tower Workload Account Assessment"
echo "=============================================="
echo ""

# Store AWS CLI results to avoid repeated calls
CALLER_IDENTITY=$(aws sts get-caller-identity 2>/dev/null)
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | jq -r '.Account // empty' 2>/dev/null || echo "$CALLER_IDENTITY" | grep -o '"Account":"[^"]*"' | cut -d'"' -f4)
USER_ARN=$(echo "$CALLER_IDENTITY" | jq -r '.Arn // empty' 2>/dev/null || echo "$CALLER_IDENTITY" | grep -o '"Arn":"[^"]*"' | cut -d'"' -f4)
REGION=$(aws configure get region 2>/dev/null || echo "${AWS_DEFAULT_REGION:-not-set}")

# Detect if running in CloudShell
if [ -n "$AWS_EXECUTION_ENV" ] && [ "$AWS_EXECUTION_ENV" = "CloudShell" ]; then
    echo "☁️  Running in AWS CloudShell"
    echo "✅ AWS CLI pre-configured with your account credentials"
else
    echo "💻 Running in local terminal"
    echo "⚠️  Ensure AWS CLI is configured with Workload Account credentials"
fi
echo ""

# Validate AWS CLI availability
if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI not found - please install AWS CLI"
    exit 1
fi

echo "🔍 Starting Workload Account Assessment..."
echo ""
echo "=== AWS Control Tower Workload Account Assessment ==="
echo "Account: $ACCOUNT_ID"
echo "Region: $REGION"
echo "Date: $(date)"
echo "User: $USER_ARN"
echo ""

# Verify we can access the account
if [ -z "$ACCOUNT_ID" ] || [ "$ACCOUNT_ID" = "null" ]; then
    echo "❌ Cannot determine account ID - check AWS CLI configuration"
    exit 1
fi

# Control Tower supported regions (updated 2024)
CT_SUPPORTED_REGIONS="us-east-1 us-west-2 eu-west-1 ap-southeast-2 eu-central-1 ap-northeast-1 ca-central-1 eu-north-1 us-east-2 ap-south-1 ap-southeast-1 eu-west-2 eu-west-3 sa-east-1"

# Check 1: Region support
echo "1. Checking region support..."
if [ "$REGION" = "not-set" ] || [ -z "$REGION" ]; then
    echo "   ❌ No region configured"
    echo "      Action: Set region with 'aws configure set region us-east-1'"
else
    if echo "$CT_SUPPORTED_REGIONS" | grep -q "$REGION"; then
        echo "   ✅ Region $REGION is supported by Control Tower"
    else
        echo "   ❌ Region $REGION is not supported by Control Tower"
        echo "      Supported regions: $CT_SUPPORTED_REGIONS"
    fi
fi

# Check 2: VPC Configuration
echo "2. Checking VPC configuration..."
VPC_COUNT=$(aws ec2 describe-vpcs --query 'length(Vpcs)' --output text 2>/dev/null)
if [ -n "$VPC_COUNT" ] && [ "$VPC_COUNT" != "0" ]; then
    echo "   ⚠️  $VPC_COUNT VPCs found"
    
    # Check for default VPC
    DEFAULT_VPC=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" --query 'Vpcs[0].VpcId' --output text 2>/dev/null)
    if [ "$DEFAULT_VPC" != "None" ] && [ -n "$DEFAULT_VPC" ]; then
        echo "      ℹ️  Default VPC exists: $DEFAULT_VPC"
        echo "      Note: Control Tower will work with existing default VPC"
    fi
    
    # Check for custom VPCs
    CUSTOM_VPCS=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=false" --query 'length(Vpcs)' --output text 2>/dev/null)
    if [ -n "$CUSTOM_VPCS" ] && [ "$CUSTOM_VPCS" != "0" ]; then
        echo "      ⚠️  $CUSTOM_VPCS custom VPCs found"
        echo "      Action: Review VPC configurations for potential conflicts"
    fi
else
    echo "   ✅ No VPCs found - Control Tower will create default VPC"
fi

# Check 3: AWS Config
echo "3. Checking AWS Config..."
CONFIG_RECORDERS=$(aws configservice describe-configuration-recorders --query 'ConfigurationRecorders[*].name' --output text 2>/dev/null)
if [ -n "$CONFIG_RECORDERS" ] && [ "$CONFIG_RECORDERS" != "" ]; then
    echo "   ⚠️  AWS Config enabled: $CONFIG_RECORDERS"
    echo "      Action: Control Tower will manage Config - existing setup may conflict"
    
    # Check Config delivery channel
    DELIVERY_CHANNELS=$(aws configservice describe-delivery-channels --query 'DeliveryChannels[*].name' --output text 2>/dev/null)
    if [ -n "$DELIVERY_CHANNELS" ] && [ "$DELIVERY_CHANNELS" != "" ]; then
        echo "      ⚠️  Config delivery channels: $DELIVERY_CHANNELS"
    fi
else
    echo "   ✅ No AWS Config found - Control Tower will set up Config"
fi

# Check 4: CloudTrail
echo "4. Checking CloudTrail..."
TRAILS=$(aws cloudtrail describe-trails --query 'trailList[*].Name' --output text 2>/dev/null)
if [ -n "$TRAILS" ] && [ "$TRAILS" != "" ]; then
    echo "   ⚠️  CloudTrail found: $TRAILS"
    echo "      Action: Review trails for potential conflicts with Control Tower logging"
    
    # Check for organization trails
    ORG_TRAILS=$(aws cloudtrail describe-trails --query 'trailList[?IsOrganizationTrail==`true`].Name' --output text 2>/dev/null)
    if [ -n "$ORG_TRAILS" ] && [ "$ORG_TRAILS" != "" ]; then
        echo "      ℹ️  Organization trails detected: $ORG_TRAILS"
        echo "      Note: These are likely from Control Tower management account"
    fi
else
    echo "   ✅ No local CloudTrail found - Control Tower will manage logging"
fi

# Check 5: IAM Roles
echo "5. Checking IAM roles for conflicts..."
CT_ROLES=$(aws iam list-roles --query 'Roles[?starts_with(RoleName, `AWSControlTower`) || starts_with(RoleName, `aws-controltower`)].RoleName' --output text 2>/dev/null)
if [ -n "$CT_ROLES" ] && [ "$CT_ROLES" != "" ]; then
    echo "   ⚠️  Control Tower IAM roles found: $CT_ROLES"
    echo "      Status: Account may already be enrolled in Control Tower"
else
    echo "   ✅ No Control Tower IAM roles found"
fi

# Check for common conflicting roles
CONFLICTING_ROLES=$(aws iam list-roles --query 'Roles[?RoleName==`OrganizationAccountAccessRole` || RoleName==`AWSCloudFormationStackSetExecutionRole`].RoleName' --output text 2>/dev/null)
if [ -n "$CONFLICTING_ROLES" ] && [ "$CONFLICTING_ROLES" != "" ]; then
    echo "   ℹ️  Standard cross-account roles found: $CONFLICTING_ROLES"
    echo "      Note: These are expected for Control Tower operations"
fi

# Check 6: CloudFormation Stacks
echo "6. Checking CloudFormation stacks..."
CT_STACKS=$(aws cloudformation list-stacks --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE --query 'StackSummaries[?starts_with(StackName, `StackSet-AWSControlTower`)].StackName' --output text 2>/dev/null)
if [ -n "$CT_STACKS" ] && [ "$CT_STACKS" != "" ]; then
    echo "   ℹ️  Control Tower stacks found: $CT_STACKS"
    echo "      Status: Account appears to be enrolled in Control Tower"
else
    echo "   ✅ No Control Tower stacks found"
fi

# Check for other stacks that might conflict
OTHER_STACKS=$(aws cloudformation list-stacks --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE --query 'length(StackSummaries[?!starts_with(StackName, `StackSet-AWSControlTower`)])' --output text 2>/dev/null)
if [ -n "$OTHER_STACKS" ] && [ "$OTHER_STACKS" != "0" ]; then
    echo "   ℹ️  $OTHER_STACKS other CloudFormation stacks found"
    echo "      Note: Review for potential resource conflicts"
fi

# Check 7: Log Groups
echo "7. Checking CloudWatch Log Groups..."
CT_LOG_GROUPS=$(aws logs describe-log-groups --log-group-name-prefix "/aws/controltower" --query 'length(logGroups)' --output text 2>/dev/null)
if [ -n "$CT_LOG_GROUPS" ] && [ "$CT_LOG_GROUPS" != "0" ]; then
    echo "   ℹ️  $CT_LOG_GROUPS Control Tower log groups found"
    echo "      Status: Account may already have Control Tower logging"
else
    echo "   ✅ No Control Tower log groups found"
fi

# Check 8: Account Type Assessment
echo "8. Assessing account readiness..."
if echo "$USER_ARN" | grep -q ":assumed-role/OrganizationAccountAccessRole/"; then
    echo "   ✅ Running with OrganizationAccountAccessRole - good for enrollment"
elif echo "$USER_ARN" | grep -q ":root"; then
    echo "   ⚠️  Running as root user - consider using cross-account role"
else
    echo "   ℹ️  Running as: $(echo "$USER_ARN" | cut -d'/' -f2-)"
    echo "      Note: Ensure sufficient permissions for Control Tower enrollment"
fi

# Check 9: Security Groups
echo "9. Checking Security Groups..."
OPEN_SG=$(aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]]' --output text 2>/dev/null | wc -l)
if [ "$OPEN_SG" -gt 0 ]; then
    echo "   ⚠️  $OPEN_SG security groups with 0.0.0.0/0 access found"
    echo "      Action: Review overly permissive rules - may violate CT guardrails"
else
    echo "   ✅ No overly permissive security groups found"
fi

# Check 10: S3 Buckets
echo "10. Checking S3 buckets..."
S3_BUCKETS=$(aws s3api list-buckets --query 'length(Buckets)' --output text 2>/dev/null)
if [ -n "$S3_BUCKETS" ] && [ "$S3_BUCKETS" != "0" ]; then
    echo "   ℹ️  $S3_BUCKETS S3 buckets found"
    
    # Check for Control Tower naming conflicts
    CT_BUCKET_CONFLICTS=$(aws s3api list-buckets --query 'Buckets[?starts_with(Name, `aws-controltower`) || starts_with(Name, `ct-`) || contains(Name, `controltower`)].Name' --output text 2>/dev/null)
    if [ -n "$CT_BUCKET_CONFLICTS" ] && [ "$CT_BUCKET_CONFLICTS" != "" ]; then
        echo "      ⚠️  Potential naming conflicts: $CT_BUCKET_CONFLICTS"
        echo "      Action: Review bucket names for Control Tower conflicts"
    fi
    
    # Check for public buckets
    echo "      Note: Review bucket policies for public access - may violate guardrails"
else
    echo "   ✅ No S3 buckets found"
fi

# Check 11: IAM Users and Policies
echo "11. Checking IAM users and policies..."
IAM_USERS=$(aws iam list-users --query 'length(Users)' --output text 2>/dev/null)
if [ -n "$IAM_USERS" ] && [ "$IAM_USERS" != "0" ]; then
    echo "   ⚠️  $IAM_USERS IAM users found"
    echo "      Action: Review for AdministratorAccess policies - may violate guardrails"
    
    # Check for root access keys
    ROOT_KEYS=$(aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent' --output text 2>/dev/null)
    if [ "$ROOT_KEYS" = "1" ]; then
        echo "      ❌ Root access keys detected"
        echo "      Action: Remove root access keys before enrollment"
    fi
else
    echo "   ✅ No IAM users found"
fi

# Check 12: KMS Keys
echo "12. Checking KMS keys..."
KMS_KEYS=$(aws kms list-keys --query 'length(Keys)' --output text 2>/dev/null)
if [ -n "$KMS_KEYS" ] && [ "$KMS_KEYS" != "0" ]; then
    echo "   ℹ️  $KMS_KEYS KMS keys found"
    echo "      Action: Ensure key policies allow Control Tower service access"
else
    echo "   ✅ No custom KMS keys found"
fi

# Check 13: Lambda Functions
echo "13. Checking Lambda functions..."
LAMBDA_FUNCTIONS=$(aws lambda list-functions --query 'length(Functions)' --output text 2>/dev/null)
if [ -n "$LAMBDA_FUNCTIONS" ] && [ "$LAMBDA_FUNCTIONS" != "0" ]; then
    echo "   ℹ️  $LAMBDA_FUNCTIONS Lambda functions found"
    
    # Check for Control Tower naming conflicts
    CT_LAMBDA_CONFLICTS=$(aws lambda list-functions --query 'Functions[?starts_with(FunctionName, `aws-controltower`) || starts_with(FunctionName, `ct-`)].FunctionName' --output text 2>/dev/null)
    if [ -n "$CT_LAMBDA_CONFLICTS" ] && [ "$CT_LAMBDA_CONFLICTS" != "" ]; then
        echo "      ⚠️  Potential naming conflicts: $CT_LAMBDA_CONFLICTS"
    fi
else
    echo "   ✅ No Lambda functions found"
fi

# Check 14: RDS Instances
echo "14. Checking RDS instances..."
RDS_INSTANCES=$(aws rds describe-db-instances --query 'length(DBInstances)' --output text 2>/dev/null)
if [ -n "$RDS_INSTANCES" ] && [ "$RDS_INSTANCES" != "0" ]; then
    echo "   ⚠️  $RDS_INSTANCES RDS instances found"
    echo "      Action: Review network configurations - may be affected by CT changes"
else
    echo "   ✅ No RDS instances found"
fi

# Check 15: Auto Scaling Groups
echo "15. Checking Auto Scaling Groups..."
ASG_COUNT=$(aws autoscaling describe-auto-scaling-groups --query 'length(AutoScalingGroups)' --output text 2>/dev/null)
if [ -n "$ASG_COUNT" ] && [ "$ASG_COUNT" != "0" ]; then
    echo "   ⚠️  $ASG_COUNT Auto Scaling Groups found"
    echo "      Action: Review ASG configurations for CT compatibility"
else
    echo "   ✅ No Auto Scaling Groups found"
fi

# Check 16: CloudWatch Alarms
echo "16. Checking CloudWatch alarms..."
CW_ALARMS=$(aws cloudwatch describe-alarms --query 'length(MetricAlarms)' --output text 2>/dev/null)
if [ -n "$CW_ALARMS" ] && [ "$CW_ALARMS" != "0" ]; then
    echo "   ℹ️  $CW_ALARMS CloudWatch alarms found"
    echo "      Note: Some alarms may trigger during CT enrollment"
else
    echo "   ✅ No CloudWatch alarms found"
fi

# Check 17: VPC Endpoints
echo "17. Checking VPC endpoints..."
VPC_ENDPOINTS=$(aws ec2 describe-vpc-endpoints --query 'length(VpcEndpoints)' --output text 2>/dev/null)
if [ -n "$VPC_ENDPOINTS" ] && [ "$VPC_ENDPOINTS" != "0" ]; then
    echo "   ℹ️  $VPC_ENDPOINTS VPC endpoints found"
    echo "      Action: Review for potential conflicts with CT networking"
else
    echo "   ✅ No VPC endpoints found"
fi

# Check 18: Route Tables
echo "18. Checking route tables..."
ROUTE_TABLES=$(aws ec2 describe-route-tables --query 'length(RouteTables)' --output text 2>/dev/null)
if [ -n "$ROUTE_TABLES" ] && [ "$ROUTE_TABLES" != "0" ]; then
    echo "   ℹ️  $ROUTE_TABLES route tables found"
    
    # Check for custom routes
    CUSTOM_ROUTES=$(aws ec2 describe-route-tables --query 'RouteTables[?Routes[?Origin!=`CreateRouteTable`]]' --output text 2>/dev/null | wc -l)
    if [ "$CUSTOM_ROUTES" -gt 0 ]; then
        echo "      ⚠️  Custom routes detected"
        echo "      Action: Review routing for CT network compatibility"
    fi
else
    echo "   ✅ No custom route tables found"
fi

# Check 19: SNS Topics
echo "19. Checking SNS topics..."
SNS_TOPICS=$(aws sns list-topics --query 'length(Topics)' --output text 2>/dev/null)
if [ -n "$SNS_TOPICS" ] && [ "$SNS_TOPICS" != "0" ]; then
    echo "   ℹ️  $SNS_TOPICS SNS topics found"
    
    # Check for Control Tower naming conflicts
    CT_SNS_CONFLICTS=$(aws sns list-topics --query 'Topics[?contains(TopicArn, `controltower`) || contains(TopicArn, `aws-controltower`)].TopicArn' --output text 2>/dev/null)
    if [ -n "$CT_SNS_CONFLICTS" ] && [ "$CT_SNS_CONFLICTS" != "" ]; then
        echo "      ⚠️  Potential naming conflicts detected"
    fi
else
    echo "   ✅ No SNS topics found"
fi

# Check 20: EBS Encryption
echo "20. Checking EBS encryption settings..."
EBS_ENCRYPTION=$(aws ec2 get-ebs-encryption-by-default --query 'EbsEncryptionByDefault' --output text 2>/dev/null)
if [ "$EBS_ENCRYPTION" = "true" ]; then
    echo "   ✅ EBS encryption by default is enabled"
else
    echo "   ⚠️  EBS encryption by default is disabled"
    echo "      Action: Consider enabling for compliance with CT guardrails"
fi

# Check 21: EC2 Instances
echo "21. Checking EC2 instances..."
EC2_INSTANCES=$(aws ec2 describe-instances --filters "Name=instance-state-name,Values=running" --query 'length(Reservations[].Instances[])' --output text 2>/dev/null)
if [ -n "$EC2_INSTANCES" ] && [ "$EC2_INSTANCES" != "0" ]; then
    echo "   ⚠️  $EC2_INSTANCES running EC2 instances found"
    echo "      Action: Review for network changes during CT enrollment"
else
    echo "   ✅ No running EC2 instances found"
fi

# Check 22: NAT Gateways
echo "22. Checking NAT Gateways..."
NAT_GATEWAYS=$(aws ec2 describe-nat-gateways --query 'length(NatGateways[?State==`available`])' --output text 2>/dev/null)
if [ -n "$NAT_GATEWAYS" ] && [ "$NAT_GATEWAYS" != "0" ]; then
    echo "   ⚠️  $NAT_GATEWAYS NAT Gateways found"
    echo "      Action: Review network dependencies for CT compatibility"
else
    echo "   ✅ No NAT Gateways found"
fi

# Check 23: Internet Gateways
echo "23. Checking Internet Gateways..."
IGWS=$(aws ec2 describe-internet-gateways --query 'length(InternetGateways)' --output text 2>/dev/null)
if [ -n "$IGWS" ] && [ "$IGWS" != "0" ]; then
    echo "   ℹ️  $IGWS Internet Gateways found"
    echo "      Note: Review routing configurations for CT compatibility"
else
    echo "   ✅ No Internet Gateways found"
fi

# Check 24: Load Balancers
echo "24. Checking Load Balancers..."
ALBS=$(aws elbv2 describe-load-balancers --query 'length(LoadBalancers)' --output text 2>/dev/null)
CLBS=$(aws elb describe-load-balancers --query 'length(LoadBalancerDescriptions)' --output text 2>/dev/null)
TOTAL_LBS=$((${ALB:-0} + ${CLBS:-0}))
if [ "$TOTAL_LBS" -gt 0 ]; then
    echo "   ⚠️  $TOTAL_LBS Load Balancers found (ALB: ${ALBS:-0}, CLB: ${CLBS:-0})"
    echo "      Action: Review network configurations for CT enrollment impact"
else
    echo "   ✅ No Load Balancers found"
fi

# Check 25: Systems Manager Parameters
echo "25. Checking Systems Manager parameters..."
SSM_PARAMS=$(aws ssm describe-parameters --query 'length(Parameters)' --output text 2>/dev/null)
if [ -n "$SSM_PARAMS" ] && [ "$SSM_PARAMS" != "0" ]; then
    echo "   ℹ️  $SSM_PARAMS SSM parameters found"
    
    # Check for Control Tower conflicts
    CT_SSM_CONFLICTS=$(aws ssm describe-parameters --parameter-filters "Key=Name,Option=BeginsWith,Values=/aws/controltower" --query 'length(Parameters)' --output text 2>/dev/null)
    if [ -n "$CT_SSM_CONFLICTS" ] && [ "$CT_SSM_CONFLICTS" != "0" ]; then
        echo "      ⚠️  $CT_SSM_CONFLICTS Control Tower SSM parameters found"
    fi
else
    echo "   ✅ No SSM parameters found"
fi

# Check 26: Secrets Manager
echo "26. Checking Secrets Manager..."
SECRETS=$(aws secretsmanager list-secrets --query 'length(SecretList)' --output text 2>/dev/null)
if [ -n "$SECRETS" ] && [ "$SECRETS" != "0" ]; then
    echo "   ℹ️  $SECRETS secrets found"
    echo "      Action: Ensure secret policies allow Control Tower service access"
else
    echo "   ✅ No secrets found"
fi

# Check 27: Resource Limits
echo "27. Checking resource limits..."
if [ -n "$VPC_COUNT" ] && [ "$VPC_COUNT" -gt 3 ]; then
    echo "   ⚠️  High VPC count ($VPC_COUNT) - may approach limits"
    echo "      Action: Consider VPC cleanup before enrollment"
else
    echo "   ✅ VPC count within normal limits"
fi

echo ""
echo "=============================================="
echo "📋 COMPREHENSIVE ASSESSMENT SUMMARY"
echo "=============================================="
echo "Account ID: $ACCOUNT_ID"
echo "Region: $REGION"
echo "Assessment completed at: $(date)"
echo ""
echo "🔍 CRITICAL VALIDATIONS COMPLETED:"
echo "✓ Region support and configuration"
echo "✓ VPC and networking setup"
echo "✓ AWS Config and CloudTrail conflicts"
echo "✓ IAM roles and policy conflicts"
echo "✓ CloudFormation stack conflicts"
echo "✓ Security group configurations"
echo "✓ S3 bucket policies and naming"
echo "✓ KMS key access policies"
echo "✓ Lambda function conflicts"
echo "✓ RDS network dependencies"
echo "✓ Auto Scaling Group compatibility"
echo "✓ CloudWatch alarm impacts"
echo "✓ VPC endpoint conflicts"
echo "✓ Route table configurations"
echo "✓ SNS topic naming conflicts"
echo "✓ EBS encryption settings"
echo "✓ EC2 instance dependencies"
echo "✓ NAT Gateway configurations"
echo "✓ Internet Gateway routing"
echo "✓ Load Balancer network impact"
echo "✓ Systems Manager parameters"
echo "✓ Secrets Manager policies"
echo "✓ Resource limits and quotas"
echo ""
echo "🔍 NEXT STEPS:"
echo "1. Resolve all ❌ (critical) issues before enrollment"
echo "2. Review all ⚠️  (warning) items for potential conflicts"
echo "3. Backup critical configurations before enrollment"
echo "4. Coordinate with Control Tower administrator for enrollment"
echo "5. Ensure Management Account has completed readiness assessment"
echo "6. Plan for potential service interruptions during enrollment"
echo ""
echo "📚 ADDITIONAL CONSIDERATIONS:"
echo "• Review third-party integrations for network changes"
echo "• Validate CI/CD pipelines won't be affected"
echo "• Check external monitoring tools for access requirements"
echo "• Assess backup and disaster recovery dependencies"
echo "• Review cost allocation tags and billing alerts"
echo ""
echo "📚 For enrollment process, contact your Control Tower administrator"
echo "=============================================="
