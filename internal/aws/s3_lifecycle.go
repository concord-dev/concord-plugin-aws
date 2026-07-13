package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectS3Lifecycle reports each S3 bucket's lifecycle rules and Object Lock
// retention, with tags. Shape:
//
//	{ fetched_at, buckets: [ { name, tags,
//	    lifecycle: { enabled, rules: [ { id, expiration_days } ] },
//	    object_lock: { enabled, default_retention_days } } ] }
//
// This backs the s3_lifecycle evidence type the SOC 2 P4.2 (data disposal)
// control reads (it requires an expiration rule on PII buckets).
func (c *Collector) collectS3Lifecycle(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	listOut, err := c.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, wrapErr("listing buckets", err)
	}
	buckets := make([]map[string]any, 0, len(listOut.Buckets))
	for _, b := range listOut.Buckets {
		buckets = append(buckets, map[string]any{
			"name":        aws.ToString(b.Name),
			"tags":        c.bucketTags(ctx, b.Name),
			"lifecycle":   c.bucketLifecycle(ctx, b.Name),
			"object_lock": c.bucketLifecycleObjectLock(ctx, b.Name),
		})
	}
	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"buckets":    buckets,
	}, nil
}

func (c *Collector) bucketLifecycle(ctx context.Context, name *string) map[string]any {
	out, err := c.s3.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: name})
	if err != nil || out == nil || len(out.Rules) == 0 {
		return map[string]any{"enabled": false, "rules": []any{}}
	}
	rules := make([]map[string]any, 0, len(out.Rules))
	for _, r := range out.Rules {
		rule := map[string]any{"id": aws.ToString(r.ID)}
		if r.Expiration != nil {
			rule["expiration_days"] = aws.ToInt32(r.Expiration.Days)
		}
		rules = append(rules, rule)
	}
	return map[string]any{"enabled": true, "rules": rules}
}

func (c *Collector) bucketLifecycleObjectLock(ctx context.Context, name *string) map[string]any {
	lock := map[string]any{"enabled": false}
	out, err := c.s3.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: name})
	if err != nil || out == nil || out.ObjectLockConfiguration == nil {
		return lock
	}
	cfg := out.ObjectLockConfiguration
	lock["enabled"] = string(cfg.ObjectLockEnabled) == "Enabled"
	if cfg.Rule != nil && cfg.Rule.DefaultRetention != nil {
		lock["default_retention_days"] = aws.ToInt32(cfg.Rule.DefaultRetention.Days)
	}
	return lock
}
