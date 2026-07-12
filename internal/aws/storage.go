package aws

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectStorageEncryption reports encryption-at-rest across S3 buckets, RDS
// instances, and EBS volumes, tagging each resource so controls can scope by
// data classification (ephi / sensitive / pci / production / fedramp). Shape:
//
//	{ fetched_at,
//	  buckets:       [ { name, tags, encryption: { configured, rules } } ],
//	  rds_instances: [ { identifier, tags, encryption: { configured } } ],
//	  ebs_volumes:   [ { volume_id, tags, encryption: { configured } } ] }
//
// This backs the storage_encryption evidence type consumed by the HIPAA,
// PCI-DSS, FedRAMP, NIST-CSF-2, and SOC 2 at-rest-encryption controls.
func (c *Collector) collectStorageEncryption(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	buckets, err := c.storageBuckets(ctx)
	if err != nil {
		return nil, err
	}
	rdsInstances, err := c.storageRDS(ctx)
	if err != nil {
		return nil, err
	}
	volumes, err := c.storageEBS(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"fetched_at":    time.Now().UTC().Format(time.RFC3339),
		"buckets":       buckets,
		"rds_instances": rdsInstances,
		"ebs_volumes":   volumes,
	}, nil
}

func (c *Collector) storageBuckets(ctx context.Context) ([]map[string]any, error) {
	listOut, err := c.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, wrapErr("listing buckets", err)
	}
	buckets := make([]map[string]any, 0, len(listOut.Buckets))
	for _, b := range listOut.Buckets {
		name := aws.ToString(b.Name)
		bucket := map[string]any{"name": name, "tags": map[string]any{}}

		encOut, err := c.s3.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: b.Name})
		switch {
		case err == nil:
			bucket["encryption"] = normalizeEncryption(encOut)
		case isNoEncryptionError(err):
			bucket["encryption"] = map[string]any{"configured": false, "rules": []any{}}
		default:
			return nil, wrapErr("getting encryption for "+name, err)
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
			// no tags configured — leave the empty map
		default:
			return nil, wrapErr("getting tags for "+name, err)
		}
		buckets = append(buckets, bucket)
	}
	return buckets, nil
}

func (c *Collector) storageRDS(ctx context.Context) ([]map[string]any, error) {
	out := make([]map[string]any, 0)
	paginator := rds.NewDescribeDBInstancesPaginator(c.rds, &rds.DescribeDBInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("describing RDS instances", err)
		}
		for _, db := range page.DBInstances {
			out = append(out, map[string]any{
				"identifier": aws.ToString(db.DBInstanceIdentifier),
				"tags":       rdsTags(db.TagList),
				"encryption": map[string]any{"configured": aws.ToBool(db.StorageEncrypted)},
			})
		}
	}
	return out, nil
}

func (c *Collector) storageEBS(ctx context.Context) ([]map[string]any, error) {
	out := make([]map[string]any, 0)
	paginator := ec2.NewDescribeVolumesPaginator(c.ec2, &ec2.DescribeVolumesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("describing EBS volumes", err)
		}
		for _, v := range page.Volumes {
			out = append(out, map[string]any{
				"volume_id":  aws.ToString(v.VolumeId),
				"tags":       ec2Tags(v.Tags),
				"encryption": map[string]any{"configured": aws.ToBool(v.Encrypted)},
			})
		}
	}
	return out, nil
}

func rdsTags(tags []rdstypes.Tag) map[string]any {
	m := map[string]any{}
	for _, t := range tags {
		m[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return m
}

func ec2Tags(tags []ec2types.Tag) map[string]any {
	m := map[string]any{}
	for _, t := range tags {
		m[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return m
}

// isNoTagsError reports the S3 "no tag set configured" condition, which
// GetBucketTagging returns as an error rather than an empty result.
func isNoTagsError(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode() == "NoSuchTagSet"
	}
	return false
}
