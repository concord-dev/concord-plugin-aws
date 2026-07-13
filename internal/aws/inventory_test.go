package aws_test

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	cfgtypes2 "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
)

func TestCollectEC2Inventory(t *testing.T) {
	c := &aws.Collector{}
	aws.WithEC2(fakeEC2{reservations: []ec2types.Reservation{{
		Instances: []ec2types.Instance{{
			InstanceId: awssdk.String("i-aaa"),
			Tags:       []ec2types.Tag{{Key: awssdk.String("environment"), Value: awssdk.String("prod")}},
		}},
	}}})(c)
	aws.WithConfig(fakeConfig{status: []cfgtypes2.ConfigurationRecorderStatus{{Recording: true}}})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "ec2_inventory"})
	require.NoError(t, err)
	m := out.(map[string]any)
	assert.Equal(t, true, m["config_recorder_active"])
	insts := m["instances"].([]map[string]any)
	require.Len(t, insts, 1)
	assert.Equal(t, "i-aaa", insts[0]["id"])
	assert.Equal(t, "prod", insts[0]["tags"].(map[string]any)["environment"])
}

type fakeCloudTrail struct {
	trails    []cttypes.Trail
	selectors []cttypes.EventSelector
	logging   bool
}

func (f fakeCloudTrail) DescribeTrails(context.Context, *cloudtrail.DescribeTrailsInput, ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error) {
	return &cloudtrail.DescribeTrailsOutput{TrailList: f.trails}, nil
}

func (f fakeCloudTrail) GetTrailStatus(context.Context, *cloudtrail.GetTrailStatusInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error) {
	return &cloudtrail.GetTrailStatusOutput{IsLogging: awssdk.Bool(f.logging)}, nil
}

func (f fakeCloudTrail) GetEventSelectors(context.Context, *cloudtrail.GetEventSelectorsInput, ...func(*cloudtrail.Options)) (*cloudtrail.GetEventSelectorsOutput, error) {
	return &cloudtrail.GetEventSelectorsOutput{EventSelectors: f.selectors}, nil
}

func TestCollectCloudTrailEventSelectors(t *testing.T) {
	c := &aws.Collector{}
	aws.WithCloudTrail(fakeCloudTrail{
		trails: []cttypes.Trail{{Name: awssdk.String("org-trail"), TrailARN: awssdk.String("arn:aws:cloudtrail:us-east-1:1:trail/org-trail")}},
		selectors: []cttypes.EventSelector{{
			IncludeManagementEvents: awssdk.Bool(true),
			ReadWriteType:           cttypes.ReadWriteTypeAll,
			DataResources:           []cttypes.DataResource{{Type: awssdk.String("AWS::S3::Object"), Values: []string{"arn:aws:s3:::data/"}}},
		}},
	})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "cloudtrail_event_selectors"})
	require.NoError(t, err)
	trails := out.(map[string]any)["trails"].([]map[string]any)
	require.Len(t, trails, 1)
	sels := trails[0]["event_selectors"].([]map[string]any)
	require.Len(t, sels, 1)
	assert.Equal(t, true, sels[0]["include_management_events"])
	assert.Equal(t, "All", sels[0]["read_write_type"])
	dr := sels[0]["data_resources"].([]map[string]any)
	assert.Equal(t, "AWS::S3::Object", dr[0]["type"])
}
