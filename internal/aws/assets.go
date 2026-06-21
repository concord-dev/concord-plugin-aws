package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
	"github.com/concord-dev/concord-plugin-sdk/plugin/evidence"
)

// CollectAssets satisfies the SDK's optional AssetEmitter capability: it reports
// the AWS resources this collector observes as assets. Only S3 buckets are
// emitted today; other evidence types yield no assets. Both S3 evidence types
// observe the same buckets — the host deduplicates on source+external_id.
func (c *Collector) CollectAssets(ctx context.Context, ref plugin.EvidenceRef) ([]evidence.Asset, error) {
	switch ref.Type {
	case "s3_bucket_encryption", "s3_public_access_block":
		return c.s3Assets(ctx)
	default:
		return nil, nil
	}
}

func (c *Collector) s3Assets(ctx context.Context) ([]evidence.Asset, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	out, err := c.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, wrapErr("listing buckets", err)
	}
	assets := make([]evidence.Asset, 0, len(out.Buckets))
	for _, b := range out.Buckets {
		name := aws.ToString(b.Name)
		if name == "" {
			continue
		}
		a := evidence.NewAsset("aws", "arn:aws:s3:::"+name, evidence.AssetCloudResource, name)
		a.Metadata = map[string]any{"service": "s3"}
		if b.CreationDate != nil {
			a.Metadata["creation_date"] = b.CreationDate.UTC().Format(time.RFC3339)
		}
		assets = append(assets, a)
	}
	return assets, nil
}
