package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectAuditTrailStatus reports a comprehensive CloudTrail posture plus the
// retention of production log groups. Shape:
//
//	{ fetched_at,
//	  cloudtrail: { trails: [ { name, is_logging, is_multi_region_trail,
//	      log_file_validation_enabled, kms_key_id, s3_bucket_is_public,
//	      include_global_service_events, include_management_events } ] },
//	  log_groups: [ { name, is_production, retention_in_days } ] }
//
// This backs the audit_trail_status evidence type read by six controls across
// FedRAMP (AU-3/AU-9/AU-12) and PCI DSS (10.1/10.3/10.5). Those controls all
// read the nested cloudtrail.trails shape (PCI 10.5 additionally reads
// log_groups), so the collector emits that single standardized shape.
//
// NOTE: s3_bucket_is_public is derived from the trail bucket's S3 Public Access
// Block — true only when a block configuration exists and does not fully block
// public access. A bucket made public purely via bucket policy/ACL without a
// Public Access Block is not flagged here (that exposure is covered by the
// s3_bucket_policy / s3_public_access_block evidence types); the field is
// reported false in that case rather than guessed.
func (c *Collector) collectAuditTrailStatus(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	trailsOut, err := c.cloudtrail.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, wrapErr("describing CloudTrail trails", err)
	}
	trails := make([]map[string]any, 0, len(trailsOut.TrailList))
	for _, t := range trailsOut.TrailList {
		name := aws.ToString(t.Name)

		logging := false
		if st, err := c.cloudtrail.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: t.TrailARN}); err == nil {
			logging = aws.ToBool(st.IsLogging)
		}

		manageEvents := false
		if sel, err := c.cloudtrail.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{TrailName: t.TrailARN}); err == nil {
			for _, s := range sel.EventSelectors {
				if aws.ToBool(s.IncludeManagementEvents) {
					manageEvents = true
					break
				}
			}
		}

		trails = append(trails, map[string]any{
			"name":                          name,
			"is_logging":                    logging,
			"is_multi_region_trail":         aws.ToBool(t.IsMultiRegionTrail),
			"log_file_validation_enabled":   aws.ToBool(t.LogFileValidationEnabled),
			"kms_key_id":                    aws.ToString(t.KmsKeyId),
			"s3_bucket_is_public":           c.s3BucketIsPublic(ctx, aws.ToString(t.S3BucketName)),
			"include_global_service_events": aws.ToBool(t.IncludeGlobalServiceEvents),
			"include_management_events":     manageEvents,
		})
	}

	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"cloudtrail": map[string]any{"trails": trails},
		"log_groups": c.auditLogGroups(ctx),
	}, nil
}

// s3BucketIsPublic reports whether the bucket's Public Access Block does not
// fully block public access. A missing block configuration (or any lookup
// error) yields false — see the collector's NOTE on the limitation.
func (c *Collector) s3BucketIsPublic(ctx context.Context, bucket string) bool {
	if bucket == "" {
		return false
	}
	out, err := c.s3.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: aws.String(bucket)})
	if err != nil || out == nil || out.PublicAccessBlockConfiguration == nil {
		return false
	}
	cfg := out.PublicAccessBlockConfiguration
	fullyBlocked := aws.ToBool(cfg.BlockPublicAcls) && aws.ToBool(cfg.IgnorePublicAcls) &&
		aws.ToBool(cfg.BlockPublicPolicy) && aws.ToBool(cfg.RestrictPublicBuckets)
	return !fullyBlocked
}

// auditLogGroups reports each log group's retention and whether it is tagged as
// production, backing PCI DSS 10.5's log-retention requirement.
func (c *Collector) auditLogGroups(ctx context.Context) []map[string]any {
	groups := make([]map[string]any, 0)
	pager := cloudwatchlogs.NewDescribeLogGroupsPaginator(c.cwlogs, &cloudwatchlogs.DescribeLogGroupsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return groups
		}
		for _, g := range page.LogGroups {
			tags := c.logGroupTags(ctx, aws.ToString(g.Arn))
			groups = append(groups, map[string]any{
				"name":              aws.ToString(g.LogGroupName),
				"is_production":     tags["production"] == "true",
				"retention_in_days": aws.ToInt32(g.RetentionInDays),
			})
		}
	}
	return groups
}
