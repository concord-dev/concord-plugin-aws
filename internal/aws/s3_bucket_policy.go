package aws

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectS3BucketPolicy reports each S3 bucket's resource policy (decoded) and
// tags. Shape:
//
//	{ fetched_at, buckets: [ { name, tags, policy } ] }
//
// This backs the s3_bucket_policy evidence type the HIPAA/PCI/ISO/NIST-CSF
// transmission-security controls read (they inspect policy.Statement for a Deny
// on aws:SecureTransport=false). A bucket with no policy yields an empty object
// so those controls fail closed.
func (c *Collector) collectS3BucketPolicy(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	listOut, err := c.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, wrapErr("listing buckets", err)
	}
	buckets := make([]map[string]any, 0, len(listOut.Buckets))
	for _, b := range listOut.Buckets {
		name := aws.ToString(b.Name)
		bucket := map[string]any{"name": name, "tags": map[string]any{}, "policy": map[string]any{}}

		polOut, err := c.s3.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: b.Name})
		switch {
		case err == nil && polOut != nil && polOut.Policy != nil:
			bucket["policy"] = decodeJSONObject(aws.ToString(polOut.Policy))
		case err == nil, isNoBucketPolicyError(err):
			// no policy — leave the empty object
		default:
			return nil, wrapErr("getting bucket policy for "+name, err)
		}

		tagOut, err := c.s3.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: b.Name})
		switch {
		case err == nil && tagOut != nil:
			tags := map[string]any{}
			for _, t := range tagOut.TagSet {
				tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
			}
			bucket["tags"] = tags
		case err == nil, isNoTagsError(err):
			// no tags — leave the empty map
		default:
			return nil, wrapErr("getting tags for "+name, err)
		}
		buckets = append(buckets, bucket)
	}
	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"buckets":    buckets,
	}, nil
}

// decodeJSONObject parses a raw JSON object string (e.g. an S3 bucket policy,
// which the API returns as plain JSON — not URL-encoded like IAM documents).
func decodeJSONObject(s string) map[string]any {
	out := map[string]any{}
	if s == "" {
		return out
	}
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// isNoBucketPolicyError reports the S3 "no policy attached" condition, which
// GetBucketPolicy returns as an error rather than an empty result.
func isNoBucketPolicyError(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == "NoSuchBucketPolicy"
	}
	return false
}
