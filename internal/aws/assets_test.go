package aws_test

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
	"github.com/concord-dev/concord-plugin-sdk/plugin/evidence"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
)

type fakeS3 struct {
	buckets []s3types.Bucket
}

func (f fakeS3) ListBuckets(_ context.Context, _ *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{Buckets: f.buckets}, nil
}

func (fakeS3) GetBucketEncryption(_ context.Context, _ *s3.GetBucketEncryptionInput, _ ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	return nil, nil
}

func (fakeS3) GetPublicAccessBlock(_ context.Context, _ *s3.GetPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	return nil, nil
}

func (fakeS3) GetBucketTagging(_ context.Context, _ *s3.GetBucketTaggingInput, _ ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	return &s3.GetBucketTaggingOutput{}, nil
}

func (fakeS3) GetBucketPolicy(_ context.Context, _ *s3.GetBucketPolicyInput, _ ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	return &s3.GetBucketPolicyOutput{}, nil
}

func TestCollectAssets_S3Buckets(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	c := &aws.Collector{}
	aws.WithS3(fakeS3{buckets: []s3types.Bucket{
		{Name: awssdk.String("prod-data"), CreationDate: &created},
		{Name: awssdk.String("logs")},
	}})(c)

	for _, typ := range []string{"s3_bucket_encryption", "s3_public_access_block"} {
		assets, err := c.CollectAssets(context.Background(), plugin.EvidenceRef{Type: typ})
		require.NoError(t, err)
		require.Len(t, assets, 2, "one asset per bucket for type %s", typ)

		assert.Equal(t, evidence.NewAsset("aws", "arn:aws:s3:::prod-data", "cloud_resource", "prod-data").Source, assets[0].Source)
		assert.Equal(t, "arn:aws:s3:::prod-data", assets[0].ExternalID)
		assert.Equal(t, "cloud_resource", assets[0].Type)
		assert.Equal(t, "prod-data", assets[0].Name)
		assert.Equal(t, "s3", assets[0].Metadata["service"])
		assert.Equal(t, "2026-01-02T03:04:05Z", assets[0].Metadata["creation_date"])
		_, hasDate := assets[1].Metadata["creation_date"]
		assert.False(t, hasDate, "bucket without creation date omits it")
	}
}

func TestCollectAssets_UnknownTypeEmitsNothing(t *testing.T) {
	c := &aws.Collector{}
	aws.WithS3(fakeS3{})(c)
	assets, err := c.CollectAssets(context.Background(), plugin.EvidenceRef{Type: "iam_account_summary"})
	require.NoError(t, err)
	assert.Empty(t, assets, "non-S3 evidence types emit no assets in this increment")
}

// The collector must satisfy the optional AssetEmitter capability.
var _ plugin.AssetEmitter = (*aws.Collector)(nil)
