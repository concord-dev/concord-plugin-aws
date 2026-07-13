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

const credReportHeader = "user,arn,user_creation_time,password_enabled,password_last_used,mfa_active," +
	"access_key_1_active,access_key_1_last_used_date,access_key_1_last_rotated," +
	"access_key_2_active,access_key_2_last_used_date,access_key_2_last_rotated"

func TestCollectIAMIdentityInventory(t *testing.T) {
	csv := credReportHeader + "\n" +
		"<root_account>,arn:root,2020-01-01T00:00:00Z,true,2025-01-01T00:00:00Z,true,false,N/A,N/A,false,N/A,N/A\n" +
		"alice,arn:alice,2024-01-01T00:00:00Z,true,2026-06-01T00:00:00Z,true,false,N/A,N/A,false,N/A,N/A\n" +
		"ci-deployer,arn:ci,2024-01-01T00:00:00Z,false,N/A,false,true,2026-06-01T00:00:00Z,2025-01-01T00:00:00Z,false,N/A,N/A"

	c := &aws.Collector{}
	aws.WithIAM(fakeIAM{credReportCSV: csv, summaryMap: map[string]int32{"AccountAccessKeysPresent": 1}})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "iam_identity_inventory"})
	require.NoError(t, err)
	m := out.(map[string]any)
	assert.Equal(t, 1, m["account_access_keys_present"])
	assert.Greater(t, m["root_last_used_days_ago"].(int), 0, "root last-used derived from the report")

	users := m["users"].([]map[string]any)
	require.Len(t, users, 2, "root_account is excluded from the user list")
	byName := map[string]map[string]any{}
	for _, u := range users {
		byName[u["username"].(string)] = u
	}
	assert.Equal(t, true, byName["alice"]["has_console_login"])
	assert.Equal(t, false, byName["alice"]["is_service_account"])
	assert.Equal(t, false, byName["ci-deployer"]["has_console_login"])
	assert.Equal(t, true, byName["ci-deployer"]["is_service_account"], "no console login => service account")
}

func TestCollectIAMPrivilegedPrincipals(t *testing.T) {
	csv := credReportHeader + "\n" +
		"admin-alice,arn:alice,2024-01-01T00:00:00Z,true,2026-06-01T00:00:00Z,true,false,N/A,N/A,false,N/A,N/A\n" +
		"reader-bob,arn:bob,2024-01-01T00:00:00Z,true,2026-06-01T00:00:00Z,false,true,2026-06-01T00:00:00Z,2025-01-01T00:00:00Z,false,N/A,N/A"

	c := &aws.Collector{}
	aws.WithIAM(fakeIAM{
		credReportCSV: csv,
		users: []iamtypes.User{
			{UserName: awssdk.String("admin-alice")},
			{UserName: awssdk.String("reader-bob")},
		},
		attachedUser: map[string][]iamtypes.AttachedPolicy{
			"admin-alice": {{PolicyName: awssdk.String("AdministratorAccess"),
				PolicyArn: awssdk.String("arn:aws:iam::aws:policy/AdministratorAccess")}},
			// reader-bob has no attached policies -> not an administrator
		},
	})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "iam_privileged_principals"})
	require.NoError(t, err)
	admins := out.(map[string]any)["administrators"].([]map[string]any)
	require.Len(t, admins, 1, "only the AdministratorAccess user is privileged")
	assert.Equal(t, "admin-alice", admins[0]["username"])
	assert.Equal(t, true, admins[0]["mfa_enabled"])
	assert.Equal(t, false, admins[0]["has_access_key"])
}
