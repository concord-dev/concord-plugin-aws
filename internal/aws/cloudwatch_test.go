package aws_test

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
)

type fakeCW struct{ alarms []cwtypes.MetricAlarm }

func (f fakeCW) DescribeAlarms(context.Context, *cloudwatch.DescribeAlarmsInput, ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error) {
	return &cloudwatch.DescribeAlarmsOutput{MetricAlarms: f.alarms}, nil
}

type fakeCWLogs struct {
	filters []cwltypes.MetricFilter
	groups  []cwltypes.LogGroup
	tags    map[string]string
}

func (f fakeCWLogs) DescribeMetricFilters(context.Context, *cloudwatchlogs.DescribeMetricFiltersInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeMetricFiltersOutput, error) {
	return &cloudwatchlogs.DescribeMetricFiltersOutput{MetricFilters: f.filters}, nil
}

func (f fakeCWLogs) DescribeLogGroups(context.Context, *cloudwatchlogs.DescribeLogGroupsInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
	return &cloudwatchlogs.DescribeLogGroupsOutput{LogGroups: f.groups}, nil
}

func (f fakeCWLogs) ListTagsForResource(context.Context, *cloudwatchlogs.ListTagsForResourceInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.ListTagsForResourceOutput, error) {
	return &cloudwatchlogs.ListTagsForResourceOutput{Tags: f.tags}, nil
}

func TestCollectCloudWatchAlarms(t *testing.T) {
	c := &aws.Collector{}
	aws.WithCloudWatchLogs(fakeCWLogs{filters: []cwltypes.MetricFilter{{
		FilterName:            awssdk.String("ConsoleLoginFailures"),
		LogGroupName:          awssdk.String("/aws/cloudtrail/org-trail"),
		FilterPattern:         awssdk.String("{ ($.eventName = ConsoleLogin) }"),
		MetricTransformations: []cwltypes.MetricTransformation{{MetricName: awssdk.String("ConsoleLoginFailureCount")}},
	}}})(c)
	aws.WithCloudWatch(fakeCW{alarms: []cwtypes.MetricAlarm{{
		AlarmName:      awssdk.String("console-login-failures"),
		MetricName:     awssdk.String("ConsoleLoginFailureCount"),
		ActionsEnabled: awssdk.Bool(true),
		AlarmActions:   []string{"arn:aws:sns:us-east-1:1:security-alerts"},
	}}})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "cloudwatch_alarms"})
	require.NoError(t, err)
	m := out.(map[string]any)
	filters := m["metric_filters"].([]map[string]any)
	require.Len(t, filters, 1)
	assert.Equal(t, "ConsoleLoginFailureCount", filters[0]["metric_name"])
	alarms := m["alarms"].([]map[string]any)
	require.Len(t, alarms, 1)
	assert.Equal(t, "console-login-failures", alarms[0]["alarm_name"])
	assert.Equal(t, true, alarms[0]["actions_enabled"])
}

func TestCollectCloudWatchLogGroups(t *testing.T) {
	c := &aws.Collector{}
	aws.WithCloudWatchLogs(fakeCWLogs{
		groups: []cwltypes.LogGroup{{
			LogGroupName:    awssdk.String("/aws/phi/api"),
			Arn:             awssdk.String("arn:aws:logs:us-east-1:1:log-group:/aws/phi/api"),
			RetentionInDays: awssdk.Int32(2557),
			KmsKeyId:        awssdk.String("arn:aws:kms:us-east-1:1:key/logs"),
		}},
		tags: map[string]string{"ephi": "true"},
	})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "cloudwatch_log_groups"})
	require.NoError(t, err)
	groups := out.(map[string]any)["log_groups"].([]map[string]any)
	require.Len(t, groups, 1)
	assert.Equal(t, "/aws/phi/api", groups[0]["name"])
	assert.Equal(t, int32(2557), groups[0]["retention_in_days"])
	assert.Equal(t, true, groups[0]["holds_ephi"], "ephi tag maps to holds_ephi")
	assert.Equal(t, false, groups[0]["is_production"])
}
