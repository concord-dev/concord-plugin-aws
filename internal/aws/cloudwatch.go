package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectCloudWatchAlarms reports CloudWatch Logs metric filters and the
// CloudWatch alarms watching them. Shape:
//
//	{ fetched_at,
//	  metric_filters: [ { filter_name, log_group_name, filter_pattern, metric_name } ],
//	  alarms: [ { alarm_name, metric_name, actions_enabled, alarm_actions } ] }
//
// This backs the cloudwatch_alarms evidence type the FedRAMP AC-7 and HIPAA
// log-in-monitoring controls read (a metric filter plus an alarm with an
// action means the event is monitored and notified).
func (c *Collector) collectCloudWatchAlarms(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	filters := make([]map[string]any, 0)
	fPager := cloudwatchlogs.NewDescribeMetricFiltersPaginator(c.cwlogs, &cloudwatchlogs.DescribeMetricFiltersInput{})
	for fPager.HasMorePages() {
		page, err := fPager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("describing metric filters", err)
		}
		for _, f := range page.MetricFilters {
			metric := ""
			if len(f.MetricTransformations) > 0 {
				metric = aws.ToString(f.MetricTransformations[0].MetricName)
			}
			filters = append(filters, map[string]any{
				"filter_name":    aws.ToString(f.FilterName),
				"log_group_name": aws.ToString(f.LogGroupName),
				"filter_pattern": aws.ToString(f.FilterPattern),
				"metric_name":    metric,
			})
		}
	}

	alarms := make([]map[string]any, 0)
	aPager := cloudwatch.NewDescribeAlarmsPaginator(c.cw, &cloudwatch.DescribeAlarmsInput{})
	for aPager.HasMorePages() {
		page, err := aPager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("describing CloudWatch alarms", err)
		}
		for _, a := range page.MetricAlarms {
			alarms = append(alarms, map[string]any{
				"alarm_name":      aws.ToString(a.AlarmName),
				"metric_name":     aws.ToString(a.MetricName),
				"actions_enabled": aws.ToBool(a.ActionsEnabled),
				"alarm_actions":   a.AlarmActions,
			})
		}
	}
	return map[string]any{
		"fetched_at":     time.Now().UTC().Format(time.RFC3339),
		"metric_filters": filters,
		"alarms":         alarms,
	}, nil
}

// collectCloudWatchLogGroups reports CloudWatch log groups with retention, KMS
// key, and classification tags. Shape:
//
//	{ fetched_at, log_groups: [ { name, retention_in_days, kms_key_id,
//	    holds_ephi, is_production } ] }
//
// This backs the cloudwatch_log_groups evidence type the HIPAA audit-controls
// and ISO 27001 controls read. holds_ephi / is_production come from the log
// group's ephi / production tags (both emitted so either pack's control works).
func (c *Collector) collectCloudWatchLogGroups(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	groups := make([]map[string]any, 0)
	pager := cloudwatchlogs.NewDescribeLogGroupsPaginator(c.cwlogs, &cloudwatchlogs.DescribeLogGroupsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("describing log groups", err)
		}
		for _, g := range page.LogGroups {
			tags := c.logGroupTags(ctx, aws.ToString(g.Arn))
			group := map[string]any{
				"name":              aws.ToString(g.LogGroupName),
				"retention_in_days": aws.ToInt32(g.RetentionInDays),
				"kms_key_id":        aws.ToString(g.KmsKeyId),
				"holds_ephi":        tags["ephi"] == "true",
				"is_production":     tags["production"] == "true",
			}
			groups = append(groups, group)
		}
	}
	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"log_groups": groups,
	}, nil
}

func (c *Collector) logGroupTags(ctx context.Context, arn string) map[string]string {
	tags := map[string]string{}
	if arn == "" {
		return tags
	}
	out, err := c.cwlogs.ListTagsForResource(ctx, &cloudwatchlogs.ListTagsForResourceInput{ResourceArn: aws.String(arn)})
	if err != nil || out == nil {
		return tags
	}
	for k, v := range out.Tags {
		tags[k] = v
	}
	return tags
}
