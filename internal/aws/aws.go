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
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
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
			"iam_policies",
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
}

// Collector reads IAM, S3, CloudTrail, RDS, and EBS evidence using the AWS
// SDK v2's standard credentials chain.
type Collector struct {
	s3         S3API
	iam        IAMAPI
	cloudtrail CloudTrailAPI
	rds        RDSAPI
	ec2        EC2API
}

type Option func(*Collector)

func WithS3(api S3API) Option { return func(c *Collector) { c.s3 = api } }

func WithIAM(api IAMAPI) Option { return func(c *Collector) { c.iam = api } }

func WithCloudTrail(api CloudTrailAPI) Option { return func(c *Collector) { c.cloudtrail = api } }

func WithRDS(api RDSAPI) Option { return func(c *Collector) { c.rds = api } }

func WithEC2(api EC2API) Option { return func(c *Collector) { c.ec2 = api } }

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
