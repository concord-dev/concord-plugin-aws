package aws_test

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	cfgtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
)

type fakeConfig struct {
	recorders []cfgtypes.ConfigurationRecorder
	status    []cfgtypes.ConfigurationRecorderStatus
}

func (f fakeConfig) DescribeConfigurationRecorders(context.Context, *configservice.DescribeConfigurationRecordersInput, ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error) {
	return &configservice.DescribeConfigurationRecordersOutput{ConfigurationRecorders: f.recorders}, nil
}

func (f fakeConfig) DescribeConfigurationRecorderStatus(context.Context, *configservice.DescribeConfigurationRecorderStatusInput, ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error) {
	return &configservice.DescribeConfigurationRecorderStatusOutput{ConfigurationRecordersStatus: f.status}, nil
}

func TestCollectConfigRecorderStatus(t *testing.T) {
	c := &aws.Collector{}
	aws.WithConfig(fakeConfig{
		recorders: []cfgtypes.ConfigurationRecorder{{
			Name:           awssdk.String("default"),
			RecordingGroup: &cfgtypes.RecordingGroup{AllSupported: true},
		}},
		status: []cfgtypes.ConfigurationRecorderStatus{{
			Name:      awssdk.String("default"),
			Recording: true,
		}},
	})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "config_recorder_status"})
	require.NoError(t, err)
	m := out.(map[string]any)
	require.NotEmpty(t, m["fetched_at"])
	require.NotNil(t, m["active_regions"])

	recorders := m["recorders"].([]map[string]any)
	require.Len(t, recorders, 1)
	assert.Equal(t, "default", recorders[0]["name"])
	assert.Equal(t, true, recorders[0]["recording"], "recording is joined from the status call by name")
	assert.Equal(t, true, recorders[0]["all_supported"])
}
