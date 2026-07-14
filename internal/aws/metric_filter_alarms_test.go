package aws_test

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
)

// fakeSNS reports confirmed-subscription counts per topic ARN.
type fakeSNS struct {
	confirmed map[string]int // topic ARN -> number of confirmed subscriptions
}

func (f fakeSNS) ListSubscriptionsByTopic(_ context.Context, in *sns.ListSubscriptionsByTopicInput, _ ...func(*sns.Options)) (*sns.ListSubscriptionsByTopicOutput, error) {
	subs := make([]snstypes.Subscription, 0)
	for i := 0; i < f.confirmed[awssdk.ToString(in.TopicArn)]; i++ {
		subs = append(subs, snstypes.Subscription{SubscriptionArn: awssdk.String("arn:aws:sns:us-east-1:1:t:sub")})
	}
	// A topic with no confirmed subs still reports a pending one, which must be excluded.
	if len(subs) == 0 {
		subs = append(subs, snstypes.Subscription{SubscriptionArn: awssdk.String("PendingConfirmation")})
	}
	return &sns.ListSubscriptionsByTopicOutput{Subscriptions: subs}, nil
}

func TestCollectMetricFilterAlarms(t *testing.T) {
	c := &aws.Collector{}
	aws.WithCloudWatchLogs(fakeCWLogs{filters: []cwltypes.MetricFilter{{
		FilterName:    awssdk.String("unauthorized-api-calls"),
		FilterPattern: awssdk.String(`{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }`),
		MetricTransformations: []cwltypes.MetricTransformation{{
			MetricNamespace: awssdk.String("CISBenchmark"),
			MetricName:      awssdk.String("UnauthorizedAPICalls"),
		}},
	}}})(c)
	aws.WithCloudWatch(fakeCW{alarms: []cwtypes.MetricAlarm{{
		AlarmName:  awssdk.String("unauthorized-api-alarm"),
		Namespace:  awssdk.String("CISBenchmark"),
		MetricName: awssdk.String("UnauthorizedAPICalls"),
		AlarmActions: []string{
			"arn:aws:sns:us-east-1:1:secops",           // subscribed
			"arn:aws:sns:us-east-1:1:noone",            // pending only -> excluded
			"arn:aws:autoscaling:us-east-1:1:policy/x", // non-SNS -> excluded
		},
	}}})(c)
	aws.WithSNS(fakeSNS{confirmed: map[string]int{"arn:aws:sns:us-east-1:1:secops": 1}})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "metric_filter_alarms"})
	require.NoError(t, err)
	m := out.(map[string]any)

	filters := m["metric_filters"].([]map[string]any)
	require.Len(t, filters, 1)
	assert.Equal(t, "unauthorized-api-calls", filters[0]["name"])

	alarms := filters[0]["alarms"].([]map[string]any)
	require.Len(t, alarms, 1)
	assert.Equal(t, "unauthorized-api-alarm", alarms[0]["name"])

	topics := alarms[0]["subscribed_topics"].([]string)
	assert.Equal(t, []string{"arn:aws:sns:us-east-1:1:secops"}, topics,
		"only SNS topics with a confirmed subscriber count")
}
