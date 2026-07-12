package aws_test

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
)

// taggedS3 returns one bucket (unencrypted) carrying an ephi tag.
type taggedS3 struct{ fakeS3 }

func (taggedS3) ListBuckets(_ context.Context, _ *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{Buckets: []s3types.Bucket{{Name: awssdk.String("phi-bucket")}}}, nil
}

func (taggedS3) GetBucketTagging(_ context.Context, _ *s3.GetBucketTaggingInput, _ ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	return &s3.GetBucketTaggingOutput{TagSet: []s3types.Tag{
		{Key: awssdk.String("ephi"), Value: awssdk.String("true")},
	}}, nil
}

type fakeRDS struct{ instances []rdstypes.DBInstance }

func (f fakeRDS) DescribeDBInstances(_ context.Context, _ *rds.DescribeDBInstancesInput, _ ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	return &rds.DescribeDBInstancesOutput{DBInstances: f.instances}, nil
}

type fakeEC2 struct {
	volumes  []ec2types.Volume
	sgs      []ec2types.SecurityGroup
	vpcs     []ec2types.Vpc
	flowLogs []ec2types.FlowLog
}

func (f fakeEC2) DescribeVolumes(_ context.Context, _ *ec2.DescribeVolumesInput, _ ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	return &ec2.DescribeVolumesOutput{Volumes: f.volumes}, nil
}

func (f fakeEC2) DescribeSecurityGroups(_ context.Context, _ *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: f.sgs}, nil
}

func (f fakeEC2) DescribeVpcs(_ context.Context, _ *ec2.DescribeVpcsInput, _ ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	return &ec2.DescribeVpcsOutput{Vpcs: f.vpcs}, nil
}

func (f fakeEC2) DescribeFlowLogs(_ context.Context, _ *ec2.DescribeFlowLogsInput, _ ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error) {
	return &ec2.DescribeFlowLogsOutput{FlowLogs: f.flowLogs}, nil
}

func TestCollectStorageEncryption(t *testing.T) {
	c := &aws.Collector{}
	aws.WithS3(taggedS3{})(c)
	aws.WithRDS(fakeRDS{instances: []rdstypes.DBInstance{
		{DBInstanceIdentifier: awssdk.String("phi-postgres"), StorageEncrypted: awssdk.Bool(true),
			TagList: []rdstypes.Tag{{Key: awssdk.String("ephi"), Value: awssdk.String("true")}}},
	}})(c)
	aws.WithEC2(fakeEC2{volumes: []ec2types.Volume{
		{VolumeId: awssdk.String("vol-abc"), Encrypted: awssdk.Bool(false)},
	}})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "storage_encryption"})
	require.NoError(t, err)
	m := out.(map[string]any)

	require.NotEmpty(t, m["fetched_at"])

	buckets := m["buckets"].([]map[string]any)
	require.Len(t, buckets, 1)
	assert.Equal(t, "phi-bucket", buckets[0]["name"])
	// tags are flattened from the S3 TagSet into a map controls can scope on.
	assert.Equal(t, "true", buckets[0]["tags"].(map[string]any)["ephi"])
	// every bucket carries an encryption object with a configured flag.
	_, hasConfigured := buckets[0]["encryption"].(map[string]any)["configured"]
	assert.True(t, hasConfigured)

	rdsInstances := m["rds_instances"].([]map[string]any)
	require.Len(t, rdsInstances, 1)
	assert.Equal(t, "phi-postgres", rdsInstances[0]["identifier"])
	assert.Equal(t, true, rdsInstances[0]["encryption"].(map[string]any)["configured"])
	assert.Equal(t, "true", rdsInstances[0]["tags"].(map[string]any)["ephi"])

	volumes := m["ebs_volumes"].([]map[string]any)
	require.Len(t, volumes, 1)
	assert.Equal(t, "vol-abc", volumes[0]["volume_id"])
	assert.Equal(t, false, volumes[0]["encryption"].(map[string]any)["configured"])
}
