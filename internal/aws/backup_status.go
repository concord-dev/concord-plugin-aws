package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectBackupStatus reports backup posture across RDS, DynamoDB, and AWS
// Backup vaults. Shape:
//
//	{ fetched_at,
//	  rds_instances:  [ { identifier, tags, backup_retention_period } ],
//	  dynamodb_tables:[ { name, tags, point_in_time_recovery_enabled } ],
//	  backup_vaults:  [ { name, locked } ] }
//
// This backs the backup_status evidence type the HIPAA §164.308(a)(7),
// FedRAMP CP-9, ISO A.5.30, and NIST-CSF PR.DS-12 backup controls read.
//
// NOTE: the packs' backup_vaults also carry holds_in_scope_data and
// restore_test_age_days, which AWS does not expose (whether a vault holds
// in-scope data is an operator classification, and restore-test recency is not
// a queryable field); the collector omits them, so those specific vault checks
// are not yet backed. The RDS retention and DynamoDB PITR checks are backed.
func (c *Collector) collectBackupStatus(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	rdsInstances, err := c.backupRDS(ctx)
	if err != nil {
		return nil, err
	}
	tables, err := c.backupDynamoDB(ctx)
	if err != nil {
		return nil, err
	}
	vaults, err := c.backupVaults(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"fetched_at":      time.Now().UTC().Format(time.RFC3339),
		"rds_instances":   rdsInstances,
		"dynamodb_tables": tables,
		"backup_vaults":   vaults,
	}, nil
}

func (c *Collector) backupRDS(ctx context.Context) ([]map[string]any, error) {
	out := make([]map[string]any, 0)
	pager := rds.NewDescribeDBInstancesPaginator(c.rds, &rds.DescribeDBInstancesInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("describing RDS instances", err)
		}
		for _, db := range page.DBInstances {
			out = append(out, map[string]any{
				"identifier":              aws.ToString(db.DBInstanceIdentifier),
				"tags":                    rdsTags(db.TagList),
				"backup_retention_period": aws.ToInt32(db.BackupRetentionPeriod),
			})
		}
	}
	return out, nil
}

func (c *Collector) backupDynamoDB(ctx context.Context) ([]map[string]any, error) {
	out := make([]map[string]any, 0)
	pager := dynamodb.NewListTablesPaginator(c.dynamodb, &dynamodb.ListTablesInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("listing DynamoDB tables", err)
		}
		for _, name := range page.TableNames {
			pitr := false
			if cb, err := c.dynamodb.DescribeContinuousBackups(ctx, &dynamodb.DescribeContinuousBackupsInput{TableName: aws.String(name)}); err == nil &&
				cb.ContinuousBackupsDescription != nil && cb.ContinuousBackupsDescription.PointInTimeRecoveryDescription != nil {
				pitr = cb.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == "ENABLED"
			}
			out = append(out, map[string]any{
				"name":                           name,
				"tags":                           c.dynamoTableTags(ctx, name),
				"point_in_time_recovery_enabled": pitr,
			})
		}
	}
	return out, nil
}

func (c *Collector) dynamoTableTags(ctx context.Context, table string) map[string]any {
	tags := map[string]any{}
	desc, err := c.dynamodb.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(table)})
	if err != nil || desc.Table == nil || desc.Table.TableArn == nil {
		return tags
	}
	out, err := c.dynamodb.ListTagsOfResource(ctx, &dynamodb.ListTagsOfResourceInput{ResourceArn: desc.Table.TableArn})
	if err != nil {
		return tags
	}
	for _, t := range out.Tags {
		tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return tags
}

func (c *Collector) backupVaults(ctx context.Context) ([]map[string]any, error) {
	out := make([]map[string]any, 0)
	pager := backup.NewListBackupVaultsPaginator(c.backup, &backup.ListBackupVaultsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("listing backup vaults", err)
		}
		for _, v := range page.BackupVaultList {
			out = append(out, map[string]any{
				"name":   aws.ToString(v.BackupVaultName),
				"locked": aws.ToBool(v.Locked),
			})
		}
	}
	return out, nil
}
