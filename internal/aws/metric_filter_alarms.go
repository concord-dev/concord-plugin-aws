package aws

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/sns"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectMetricFilterAlarms links CloudWatch Logs metric filters to the alarms
// watching their metric and to the SNS topics those alarms actually notify.
// Shape:
//
//	{ fetched_at,
//	  metric_filters: [ { name, filter_pattern,
//	                      alarms: [ { name, subscribed_topics: [arn] } ] } ] }
//
// This backs the metric_filter_alarms evidence type the CIS AWS 6.x monitoring
// controls read (e.g. 6.1 unauthorized-API-call alarm). The chain a control
// checks — a metric filter matching a pattern, an alarm on that metric, and an
// SNS topic with a subscriber so the alarm can page — is resolved here:
// subscribed_topics lists only alarm action topics that have at least one
// confirmed subscription, so an alarm that can never notify surfaces as an
// empty subscribed_topics list.
func (c *Collector) collectMetricFilterAlarms(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	alarmsByMetric, err := c.alarmsByMetric(ctx)
	if err != nil {
		return nil, err
	}

	filters := make([]map[string]any, 0)
	pager := cloudwatchlogs.NewDescribeMetricFiltersPaginator(c.cwlogs, &cloudwatchlogs.DescribeMetricFiltersInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("describing metric filters", err)
		}
		for _, f := range page.MetricFilters {
			alarms := make([]map[string]any, 0)
			for _, mt := range f.MetricTransformations {
				key := metricKey(aws.ToString(mt.MetricNamespace), aws.ToString(mt.MetricName))
				for _, al := range alarmsByMetric[key] {
					alarms = append(alarms, map[string]any{
						"name":              al.name,
						"subscribed_topics": c.subscribedTopics(ctx, al.actions),
					})
				}
			}
			filters = append(filters, map[string]any{
				"name":           aws.ToString(f.FilterName),
				"filter_pattern": aws.ToString(f.FilterPattern),
				"alarms":         alarms,
			})
		}
	}
	return map[string]any{
		"fetched_at":     time.Now().UTC().Format(time.RFC3339),
		"metric_filters": filters,
	}, nil
}

type alarmInfo struct {
	name    string
	actions []string
}

func metricKey(namespace, metric string) string {
	return namespace + "\x00" + metric
}

// alarmsByMetric indexes every metric alarm by its (namespace, metric) so a
// metric filter's transformation can find the alarms watching it.
func (c *Collector) alarmsByMetric(ctx context.Context) (map[string][]alarmInfo, error) {
	out := map[string][]alarmInfo{}
	pager := cloudwatch.NewDescribeAlarmsPaginator(c.cw, &cloudwatch.DescribeAlarmsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("describing CloudWatch alarms", err)
		}
		for _, a := range page.MetricAlarms {
			key := metricKey(aws.ToString(a.Namespace), aws.ToString(a.MetricName))
			out[key] = append(out[key], alarmInfo{name: aws.ToString(a.AlarmName), actions: a.AlarmActions})
		}
	}
	return out, nil
}

// subscribedTopics returns the alarm action ARNs that are SNS topics with at
// least one confirmed subscription. Non-SNS actions (Auto Scaling, EC2, etc.)
// and topics with no confirmed subscriber are excluded, so the downstream
// control can tell whether the alarm can actually reach a human.
func (c *Collector) subscribedTopics(ctx context.Context, actions []string) []string {
	topics := make([]string, 0)
	for _, a := range actions {
		if !strings.HasPrefix(a, "arn:aws:sns:") {
			continue
		}
		if c.topicHasSubscribers(ctx, a) {
			topics = append(topics, a)
		}
	}
	return topics
}

func (c *Collector) topicHasSubscribers(ctx context.Context, topicARN string) bool {
	pager := sns.NewListSubscriptionsByTopicPaginator(c.sns, &sns.ListSubscriptionsByTopicInput{TopicArn: aws.String(topicARN)})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return false
		}
		for _, s := range page.Subscriptions {
			// A subscription is only live once confirmed; pending ones never deliver.
			if arn := aws.ToString(s.SubscriptionArn); arn != "" && arn != "PendingConfirmation" {
				return true
			}
		}
	}
	return false
}
