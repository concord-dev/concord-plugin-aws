package aws_test

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
)

func TestCollectIAMPolicies(t *testing.T) {
	adminArn := "arn:aws:iam::aws:policy/AdministratorAccess"
	// A wildcard admin policy document, URL-encoded as the IAM API returns it.
	encodedAdmin := "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22%2A%22%2C%22Resource%22%3A%22%2A%22%7D%5D%7D"

	c := &aws.Collector{}
	aws.WithIAM(fakeIAM{
		users: []iamtypes.User{{UserName: awssdk.String("billing-app")}},
		attachedUser: map[string][]iamtypes.AttachedPolicy{
			"billing-app": {{PolicyName: awssdk.String("AdministratorAccess"), PolicyArn: awssdk.String(adminArn)}},
		},
		policyVersions: map[string]string{adminArn: "v1"},
		policyDocs:     map[string]string{adminArn: encodedAdmin},
	})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "iam_policies"})
	require.NoError(t, err)
	m := out.(map[string]any)
	require.NotEmpty(t, m["fetched_at"])

	ids := m["identities"].([]map[string]any)
	require.Len(t, ids, 1)
	assert.Equal(t, "billing-app", ids[0]["name"])
	assert.Equal(t, "user", ids[0]["type"])

	attached := ids[0]["attached_policies"].([]map[string]any)
	require.Len(t, attached, 1)
	assert.Equal(t, "AdministratorAccess", attached[0]["policy_name"])
	assert.Equal(t, true, attached[0]["is_aws_managed"], "aws-managed ARN is detected")

	// the URL-encoded document is decoded so least-privilege rules can inspect it
	doc := attached[0]["document"].(map[string]any)
	stmts := doc["Statement"].([]any)
	require.Len(t, stmts, 1)
	assert.Equal(t, "*", stmts[0].(map[string]any)["Action"])
}
