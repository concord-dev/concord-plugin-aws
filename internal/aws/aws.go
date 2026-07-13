// Package aws implements the Concord collector for AWS evidence (IAM, S3,
// CloudTrail, RDS, EBS) using the AWS SDK v2's standard credentials chain.
package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/smithy-go"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

func (c *Collector) Capabilities() plugin.Capabilities {
	return plugin.Capabilities{
		Source:  "aws",
		Version: "v0.2.0",
		SupportedTypes: []string{
			"s3_bucket_encryption", "s3_public_access_block",
			"iam_account_summary", "iam_password_policy", "iam_credential_report",
			"cloudtrail_trails", "storage_encryption", "security_groups", "iam_roles",
			"iam_policies", "s3_bucket_policy", "vpc_flow_logs",
			"config_recorder_status", "guardduty_status", "ssm_patch_compliance",
			"kms_keys", "network_acls", "s3_bucket_integrity",
			"ec2_inventory", "cloudtrail_event_selectors",
		},
		OptionalEnv: []string{"AWS_REGION", "AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"},
		Permissions: plugin.Permissions{
			Network:    []string{"*.amazonaws.com"},
			Filesystem: "read-only:~/.aws",
		},
		DocsURL: "https://github.com/concord-dev/concord-plugin-aws",
	}
}

type S3API interface {
	ListBuckets(ctx context.Context, in *s3.ListBucketsInput, opts ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketEncryption(ctx context.Context, in *s3.GetBucketEncryptionInput, opts ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
	GetPublicAccessBlock(ctx context.Context, in *s3.GetPublicAccessBlockInput, opts ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketTagging(ctx context.Context, in *s3.GetBucketTaggingInput, opts ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error)
	GetBucketPolicy(ctx context.Context, in *s3.GetBucketPolicyInput, opts ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error)
	GetBucketVersioning(ctx context.Context, in *s3.GetBucketVersioningInput, opts ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	GetObjectLockConfiguration(ctx context.Context, in *s3.GetObjectLockConfigurationInput, opts ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error)
}

// RDSAPI is the subset of the RDS client the storage_encryption collector uses.
type RDSAPI interface {
	DescribeDBInstances(ctx context.Context, in *rds.DescribeDBInstancesInput, opts ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
}

// EC2API is the subset of the EC2 client the storage_encryption and
// security_groups collectors use.
type EC2API interface {
	DescribeVolumes(ctx context.Context, in *ec2.DescribeVolumesInput, opts ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
	DescribeSecurityGroups(ctx context.Context, in *ec2.DescribeSecurityGroupsInput, opts ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeVpcs(ctx context.Context, in *ec2.DescribeVpcsInput, opts ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
	DescribeFlowLogs(ctx context.Context, in *ec2.DescribeFlowLogsInput, opts ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error)
	DescribeNetworkAcls(ctx context.Context, in *ec2.DescribeNetworkAclsInput, opts ...func(*ec2.Options)) (*ec2.DescribeNetworkAclsOutput, error)
	DescribeInstances(ctx context.Context, in *ec2.DescribeInstancesInput, opts ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

type IAMAPI interface {
	GetAccountSummary(ctx context.Context, in *iam.GetAccountSummaryInput, opts ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error)
	GetAccountPasswordPolicy(ctx context.Context, in *iam.GetAccountPasswordPolicyInput, opts ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error)
	GenerateCredentialReport(ctx context.Context, in *iam.GenerateCredentialReportInput, opts ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error)
	GetCredentialReport(ctx context.Context, in *iam.GetCredentialReportInput, opts ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error)
	ListRoles(ctx context.Context, in *iam.ListRolesInput, opts ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	ListRoleTags(ctx context.Context, in *iam.ListRoleTagsInput, opts ...func(*iam.Options)) (*iam.ListRoleTagsOutput, error)
	ListUsers(ctx context.Context, in *iam.ListUsersInput, opts ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	ListGroups(ctx context.Context, in *iam.ListGroupsInput, opts ...func(*iam.Options)) (*iam.ListGroupsOutput, error)
	ListAttachedUserPolicies(ctx context.Context, in *iam.ListAttachedUserPoliciesInput, opts ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
	ListAttachedRolePolicies(ctx context.Context, in *iam.ListAttachedRolePoliciesInput, opts ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListAttachedGroupPolicies(ctx context.Context, in *iam.ListAttachedGroupPoliciesInput, opts ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error)
	GetPolicy(ctx context.Context, in *iam.GetPolicyInput, opts ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(ctx context.Context, in *iam.GetPolicyVersionInput, opts ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

type CloudTrailAPI interface {
	DescribeTrails(ctx context.Context, in *cloudtrail.DescribeTrailsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error)
	GetTrailStatus(ctx context.Context, in *cloudtrail.GetTrailStatusInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
	GetEventSelectors(ctx context.Context, in *cloudtrail.GetEventSelectorsInput, opts ...func(*cloudtrail.Options)) (*cloudtrail.GetEventSelectorsOutput, error)
}

// ConfigAPI is the subset of the AWS Config client the config_recorder_status
// collector uses.
type ConfigAPI interface {
	DescribeConfigurationRecorders(ctx context.Context, in *configservice.DescribeConfigurationRecordersInput, opts ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error)
	DescribeConfigurationRecorderStatus(ctx context.Context, in *configservice.DescribeConfigurationRecorderStatusInput, opts ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error)
}

// GuardDutyAPI is the subset of the GuardDuty client the guardduty_status
// collector uses.
type GuardDutyAPI interface {
	ListDetectors(ctx context.Context, in *guardduty.ListDetectorsInput, opts ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error)
	GetDetector(ctx context.Context, in *guardduty.GetDetectorInput, opts ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error)
}

// SSMAPI is the subset of the SSM client the ssm_patch_compliance collector uses.
type SSMAPI interface {
	DescribeInstancePatchStates(ctx context.Context, in *ssm.DescribeInstancePatchStatesInput, opts ...func(*ssm.Options)) (*ssm.DescribeInstancePatchStatesOutput, error)
}

// KMSAPI is the subset of the KMS client the kms_keys collector uses.
type KMSAPI interface {
	ListKeys(ctx context.Context, in *kms.ListKeysInput, opts ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, opts ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetKeyRotationStatus(ctx context.Context, in *kms.GetKeyRotationStatusInput, opts ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
	ListResourceTags(ctx context.Context, in *kms.ListResourceTagsInput, opts ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error)
}

// Collector reads IAM, S3, CloudTrail, RDS, and EBS evidence using the AWS
// SDK v2's standard credentials chain.
type Collector struct {
	s3         S3API
	iam        IAMAPI
	cloudtrail CloudTrailAPI
	rds        RDSAPI
	ec2        EC2API
	config     ConfigAPI
	guardduty  GuardDutyAPI
	ssm        SSMAPI
	kms        KMSAPI
	region     string
}

type Option func(*Collector)

func WithS3(api S3API) Option { return func(c *Collector) { c.s3 = api } }

func WithIAM(api IAMAPI) Option { return func(c *Collector) { c.iam = api } }

func WithCloudTrail(api CloudTrailAPI) Option { return func(c *Collector) { c.cloudtrail = api } }

func WithRDS(api RDSAPI) Option { return func(c *Collector) { c.rds = api } }

func WithEC2(api EC2API) Option { return func(c *Collector) { c.ec2 = api } }

func WithConfig(api ConfigAPI) Option { return func(c *Collector) { c.config = api } }

func WithGuardDuty(api GuardDutyAPI) Option { return func(c *Collector) { c.guardduty = api } }

func WithSSM(api SSMAPI) Option { return func(c *Collector) { c.ssm = api } }

func WithKMS(api KMSAPI) Option { return func(c *Collector) { c.kms = api } }

// New returns an AWS collector wired to the real AWS SDK clients for the given
// region (defaulting to us-east-1 when empty).
func New(ctx context.Context, region string) (*Collector, error) {
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	return &Collector{
		s3:         s3.NewFromConfig(cfg),
		iam:        iam.NewFromConfig(cfg),
		cloudtrail: cloudtrail.NewFromConfig(cfg),
		rds:        rds.NewFromConfig(cfg),
		ec2:        ec2.NewFromConfig(cfg),
		config:     configservice.NewFromConfig(cfg),
		guardduty:  guardduty.NewFromConfig(cfg),
		ssm:        ssm.NewFromConfig(cfg),
		kms:        kms.NewFromConfig(cfg),
		region:     region,
	}, nil
}

func (c *Collector) Probe(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := c.iam.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return "", wrapErr("probe", err)
	}
	users := out.SummaryMap["Users"]
	return fmt.Sprintf("iam reachable (%d users)", users), nil
}

func (c *Collector) Collect(ctx context.Context, ref plugin.EvidenceRef) (any, error) {
	switch ref.Type {
	case "s3_bucket_encryption":
		return c.collectS3BucketEncryption(ref)
	case "s3_public_access_block":
		return c.collectS3PublicAccessBlock(ref)
	case "iam_account_summary":
		return c.collectIAMAccountSummary(ref)
	case "iam_password_policy":
		return c.collectIAMPasswordPolicy(ref)
	case "iam_credential_report":
		return c.collectIAMCredentialReport(ref)
	case "cloudtrail_trails":
		return c.collectCloudTrailTrails(ref)
	case "storage_encryption":
		return c.collectStorageEncryption(ref)
	case "security_groups":
		return c.collectSecurityGroups(ref)
	case "iam_roles":
		return c.collectIAMRoles(ref)
	case "iam_policies":
		return c.collectIAMPolicies(ref)
	case "s3_bucket_policy":
		return c.collectS3BucketPolicy(ref)
	case "vpc_flow_logs":
		return c.collectVPCFlowLogs(ref)
	case "config_recorder_status":
		return c.collectConfigRecorderStatus(ref)
	case "guardduty_status":
		return c.collectGuardDutyStatus(ref)
	case "ssm_patch_compliance":
		return c.collectSSMPatchCompliance(ref)
	case "kms_keys":
		return c.collectKMSKeys(ref)
	case "network_acls":
		return c.collectNetworkACLs(ref)
	case "s3_bucket_integrity":
		return c.collectS3BucketIntegrity(ref)
	case "ec2_inventory":
		return c.collectEC2Inventory(ref)
	case "cloudtrail_event_selectors":
		return c.collectCloudTrailEventSelectors(ref)
	case "":
		return nil, fmt.Errorf("aws collector requires evidence type")
	default:
		return nil, fmt.Errorf("%w: aws collector does not handle type %q", plugin.ErrUnsupportedType, ref.Type)
	}
}

func wrapErr(stage string, err error) error {
	if err == nil {
		return nil
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		if code == "AccessDenied" || code == "AccessDeniedException" {
			if action := extractDeniedAction(apiErr.ErrorMessage()); action != "" {
				return fmt.Errorf("%s: missing IAM permission %q — attach a policy with this action (see examples/iam-readonly-policy.json)", stage, action)
			}
			return fmt.Errorf("%s: access denied — %s", stage, apiErr.ErrorMessage())
		}
	}
	if msg := err.Error(); strings.Contains(msg, "failed to refresh cached credentials") || strings.Contains(msg, "no EC2 IMDS role found") {
		return fmt.Errorf("%s: no usable AWS credentials — set AWS_PROFILE, AWS_ACCESS_KEY_ID, or run from an instance with an IAM role", stage)
	}
	return fmt.Errorf("%s: %w", stage, err)
}

func extractDeniedAction(msg string) string {
	const marker = "is not authorized to perform: "
	i := strings.Index(msg, marker)
	if i < 0 {
		return ""
	}
	rest := msg[i+len(marker):]
	end := strings.IndexAny(rest, " \t\n")
	if end < 0 {
		return rest
	}
	return rest[:end]
}
