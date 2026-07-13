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

// fakeIAM implements the full IAMAPI. Role fields drive the iam_roles test;
// user/attached/policy fields drive the iam_policies test.
type fakeIAM struct {
	roles          []iamtypes.Role
	tags           map[string][]iamtypes.Tag
	users          []iamtypes.User
	groups         []iamtypes.Group
	attachedUser   map[string][]iamtypes.AttachedPolicy
	attachedRole   map[string][]iamtypes.AttachedPolicy
	attachedGroup  map[string][]iamtypes.AttachedPolicy
	policyVersions map[string]string // arn -> default version id
	policyDocs     map[string]string // arn -> URL-encoded document
	credReportCSV  string
	summaryMap     map[string]int32
}

func (f fakeIAM) GetAccountSummary(context.Context, *iam.GetAccountSummaryInput, ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	return &iam.GetAccountSummaryOutput{SummaryMap: f.summaryMap}, nil
}

func (fakeIAM) GetAccountPasswordPolicy(context.Context, *iam.GetAccountPasswordPolicyInput, ...func(*iam.Options)) (*iam.GetAccountPasswordPolicyOutput, error) {
	return &iam.GetAccountPasswordPolicyOutput{}, nil
}

func (fakeIAM) GenerateCredentialReport(context.Context, *iam.GenerateCredentialReportInput, ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error) {
	return &iam.GenerateCredentialReportOutput{}, nil
}

func (f fakeIAM) GetCredentialReport(context.Context, *iam.GetCredentialReportInput, ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error) {
	return &iam.GetCredentialReportOutput{Content: []byte(f.credReportCSV)}, nil
}

func (f fakeIAM) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return &iam.ListRolesOutput{Roles: f.roles}, nil
}

func (f fakeIAM) ListRoleTags(_ context.Context, in *iam.ListRoleTagsInput, _ ...func(*iam.Options)) (*iam.ListRoleTagsOutput, error) {
	return &iam.ListRoleTagsOutput{Tags: f.tags[awssdk.ToString(in.RoleName)]}, nil
}

func (f fakeIAM) ListUsers(context.Context, *iam.ListUsersInput, ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	return &iam.ListUsersOutput{Users: f.users}, nil
}

func (f fakeIAM) ListGroups(context.Context, *iam.ListGroupsInput, ...func(*iam.Options)) (*iam.ListGroupsOutput, error) {
	return &iam.ListGroupsOutput{Groups: f.groups}, nil
}

func (f fakeIAM) ListAttachedUserPolicies(_ context.Context, in *iam.ListAttachedUserPoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	return &iam.ListAttachedUserPoliciesOutput{AttachedPolicies: f.attachedUser[awssdk.ToString(in.UserName)]}, nil
}

func (f fakeIAM) ListAttachedRolePolicies(_ context.Context, in *iam.ListAttachedRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: f.attachedRole[awssdk.ToString(in.RoleName)]}, nil
}

func (f fakeIAM) ListAttachedGroupPolicies(_ context.Context, in *iam.ListAttachedGroupPoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error) {
	return &iam.ListAttachedGroupPoliciesOutput{AttachedPolicies: f.attachedGroup[awssdk.ToString(in.GroupName)]}, nil
}

func (f fakeIAM) GetPolicy(_ context.Context, in *iam.GetPolicyInput, _ ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	arn := awssdk.ToString(in.PolicyArn)
	return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{
		Arn:              in.PolicyArn,
		DefaultVersionId: awssdk.String(f.policyVersions[arn]),
	}}, nil
}

func (f fakeIAM) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	arn := awssdk.ToString(in.PolicyArn)
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{
		Document:  awssdk.String(f.policyDocs[arn]),
		VersionId: in.VersionId,
	}}, nil
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
