package aws_test

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
)

type fakeBackup struct {
	vaults []backuptypes.BackupVaultListMember
}

func (f fakeBackup) ListBackupVaults(context.Context, *backup.ListBackupVaultsInput, ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error) {
	return &backup.ListBackupVaultsOutput{BackupVaultList: f.vaults}, nil
}

type fakeDynamoDB struct {
	tables []string
	pitr   bool
}

func (f fakeDynamoDB) ListTables(context.Context, *dynamodb.ListTablesInput, ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
	return &dynamodb.ListTablesOutput{TableNames: f.tables}, nil
}

func (f fakeDynamoDB) DescribeContinuousBackups(context.Context, *dynamodb.DescribeContinuousBackupsInput, ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
	status := ddbtypes.PointInTimeRecoveryStatusDisabled
	if f.pitr {
		status = ddbtypes.PointInTimeRecoveryStatusEnabled
	}
	return &dynamodb.DescribeContinuousBackupsOutput{ContinuousBackupsDescription: &ddbtypes.ContinuousBackupsDescription{
		PointInTimeRecoveryDescription: &ddbtypes.PointInTimeRecoveryDescription{PointInTimeRecoveryStatus: status},
	}}, nil
}

func (f fakeDynamoDB) DescribeTable(_ context.Context, in *dynamodb.DescribeTableInput, _ ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	return &dynamodb.DescribeTableOutput{Table: &ddbtypes.TableDescription{TableArn: awssdk.String("arn:aws:dynamodb:us-east-1:1:table/" + awssdk.ToString(in.TableName))}}, nil
}

func (f fakeDynamoDB) ListTagsOfResource(context.Context, *dynamodb.ListTagsOfResourceInput, ...func(*dynamodb.Options)) (*dynamodb.ListTagsOfResourceOutput, error) {
	return &dynamodb.ListTagsOfResourceOutput{Tags: []ddbtypes.Tag{{Key: awssdk.String("ephi"), Value: awssdk.String("true")}}}, nil
}

func TestCollectBackupStatus(t *testing.T) {
	c := &aws.Collector{}
	aws.WithRDS(fakeRDS{instances: []rdstypes.DBInstance{
		{DBInstanceIdentifier: awssdk.String("phi-postgres"), BackupRetentionPeriod: awssdk.Int32(35),
			TagList: []rdstypes.Tag{{Key: awssdk.String("ephi"), Value: awssdk.String("true")}}},
	}})(c)
	aws.WithDynamoDB(fakeDynamoDB{tables: []string{"phi-events"}, pitr: true})(c)
	aws.WithBackup(fakeBackup{vaults: []backuptypes.BackupVaultListMember{
		{BackupVaultName: awssdk.String("phi-vault"), Locked: awssdk.Bool(true)},
	}})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "backup_status"})
	require.NoError(t, err)
	m := out.(map[string]any)

	rdsI := m["rds_instances"].([]map[string]any)
	require.Len(t, rdsI, 1)
	assert.Equal(t, int32(35), rdsI[0]["backup_retention_period"])
	assert.Equal(t, "true", rdsI[0]["tags"].(map[string]any)["ephi"])

	tables := m["dynamodb_tables"].([]map[string]any)
	require.Len(t, tables, 1)
	assert.Equal(t, "phi-events", tables[0]["name"])
	assert.Equal(t, true, tables[0]["point_in_time_recovery_enabled"])

	vaults := m["backup_vaults"].([]map[string]any)
	require.Len(t, vaults, 1)
	assert.Equal(t, "phi-vault", vaults[0]["name"])
	assert.Equal(t, true, vaults[0]["locked"])
}
