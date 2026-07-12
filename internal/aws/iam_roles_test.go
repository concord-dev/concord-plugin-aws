package aws_test

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
)

// fakeIAM implements the full IAMAPI; only the role calls are exercised here.
type fakeIAM struct {
	roles []iamtypes.Role
	tags  map[string][]iamtypes.Tag
}

func (fakeIAM) GetAccountSummary(context.Context, *iam.GetAccountSummaryInput, ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	return &iam.GetAccountSummaryOutput{}, nil
}

func (fakeIAM) GetAccountPasswordPolicy(context.Context, *iam.GetAccountPasswordPolicyInput, ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error) {
	return &iam.GetAccountPasswordPolicyOutput{}, nil
}

func (fakeIAM) GenerateCredentialReport(context.Context, *iam.GenerateCredentialReportInput, ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error) {
	return &iam.GenerateCredentialReportOutput{}, nil
}

func (fakeIAM) GetCredentialReport(context.Context, *iam.GetCredentialReportInput, ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error) {
	return &iam.GetCredentialReportOutput{}, nil
}

func (f fakeIAM) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return &iam.ListRolesOutput{Roles: f.roles}, nil
}

func (f fakeIAM) ListRoleTags(_ context.Context, in *iam.ListRoleTagsInput, _ ...func(*iam.Options)) (*iam.ListRoleTagsOutput, error) {
	return &iam.ListRoleTagsOutput{Tags: f.tags[awssdk.ToString(in.RoleName)]}, nil
}

func TestCollectIAMRoles(t *testing.T) {
	// AssumeRolePolicyDocument arrives URL-encoded from the IAM API.
	encodedTrust := "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%7D%5D%7D"

	c := &aws.Collector{}
	aws.WithIAM(fakeIAM{
		roles: []iamtypes.Role{{
			RoleName:                 awssdk.String("break-glass"),
			Arn:                      awssdk.String("arn:aws:iam::123456789012:role/break-glass"),
			MaxSessionDuration:       awssdk.Int32(3600),
			AssumeRolePolicyDocument: awssdk.String(encodedTrust),
		}},
		tags: map[string][]iamtypes.Tag{
			"break-glass": {{Key: awssdk.String("ephi"), Value: awssdk.String("true")}},
		},
	})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "iam_roles"})
	require.NoError(t, err)
	m := out.(map[string]any)
	require.NotEmpty(t, m["fetched_at"])

	roles := m["roles"].([]map[string]any)
	require.Len(t, roles, 1)
	assert.Equal(t, "break-glass", roles[0]["role_name"])
	assert.Equal(t, int32(3600), roles[0]["max_session_duration_seconds"])
	assert.Equal(t, "true", roles[0]["tags"].(map[string]any)["ephi"])

	// the URL-encoded trust document is decoded into a structured object
	trust := roles[0]["assume_role_policy"].(map[string]any)
	assert.Equal(t, "2012-10-17", trust["Version"])
}
