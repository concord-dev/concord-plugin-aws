package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectS3BucketIntegrity reports each S3 bucket's versioning and Object Lock
// posture, plus tags. Shape:
//
//	{ fetched_at, buckets: [ { name, tags,
//	    versioning: { enabled, mfa_delete },
//	    object_lock: { enabled, mode, retention_days } } ] }
//
// This backs the s3_bucket_integrity evidence type the HIPAA integrity control
// reads (it requires versioning + Object Lock on ePHI buckets so overwrites are
// recoverable and tamper-resistant).
func (c *Collector) collectS3BucketIntegrity(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	listOut, err := c.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, wrapErr("listing buckets", err)
	}
	buckets := make([]map[string]any, 0, len(listOut.Buckets))
	for _, b := range listOut.Buckets {
		name := aws.ToString(b.Name)
		bucket := map[string]any{
			"name":        name,
			"tags":        c.bucketTags(ctx, b.Name),
			"versioning":  c.bucketVersioning(ctx, b.Name),
			"object_lock": c.bucketObjectLock(ctx, b.Name),
		}
		buckets = append(buckets, bucket)
	}
	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"buckets":    buckets,
	}, nil
}

func (c *Collector) bucketTags(ctx context.Context, name *string) map[string]any {
	tags := map[string]any{}
	out, err := c.s3.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: name})
	if err != nil || out == nil {
		return tags
	}
	for _, t := range out.TagSet {
		tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return tags
}

func (c *Collector) bucketVersioning(ctx context.Context, name *string) map[string]any {
	out, err := c.s3.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: name})
	if err != nil || out == nil {
		return map[string]any{"enabled": false, "mfa_delete": "Disabled"}
	}
	return map[string]any{
		"enabled":    out.Status == s3types.BucketVersioningStatusEnabled,
		"mfa_delete": string(out.MFADelete),
	}
}

func (c *Collector) bucketObjectLock(ctx context.Context, name *string) map[string]any {
	lock := map[string]any{"enabled": false}
	out, err := c.s3.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: name})
	if err != nil || out == nil || out.ObjectLockConfiguration == nil {
		return lock
	}
	cfg := out.ObjectLockConfiguration
	lock["enabled"] = cfg.ObjectLockEnabled == s3types.ObjectLockEnabledEnabled
	if cfg.Rule != nil && cfg.Rule.DefaultRetention != nil {
		lock["mode"] = string(cfg.Rule.DefaultRetention.Mode)
		lock["retention_days"] = aws.ToInt32(cfg.Rule.DefaultRetention.Days)
	}
	return lock
}
