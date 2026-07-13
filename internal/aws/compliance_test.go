package aws_test

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	cfgtypes3 "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
)

func TestCollectConfigConformanceStatus(t *testing.T) {
	c := &aws.Collector{}
	aws.WithConfig(fakeConfig{
		packs: []cfgtypes3.ConformancePackDetail{{ConformancePackName: awssdk.String("fedramp-pack")}},
		compliance: []cfgtypes3.ConformancePackComplianceSummary{{
			ConformancePackName:             awssdk.String("fedramp-pack"),
			ConformancePackComplianceStatus: cfgtypes3.ConformancePackComplianceTypeCompliant,
		}},
		recorders: []cfgtypes3.ConfigurationRecorder{{Name: awssdk.String("default"), RecordingGroup: &cfgtypes3.RecordingGroup{AllSupported: true}}},
		status:    []cfgtypes3.ConfigurationRecorderStatus{{Name: awssdk.String("default"), Recording: true}},
	})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "config_conformance_status"})
	require.NoError(t, err)
	m := out.(map[string]any)
	packs := m["conformance_packs"].([]map[string]any)
	require.Len(t, packs, 1)
	assert.Equal(t, "fedramp-pack", packs[0]["name"])
	assert.Equal(t, "COMPLIANT", packs[0]["compliance_state"])
	// recorders are emitted too (superset satisfying the pci-dss shape)
	assert.Len(t, m["recorders"].([]map[string]any), 1)
}

// lifecycleS3 returns one bucket with a lifecycle expiration rule.
type lifecycleS3 struct{ fakeS3 }

func (lifecycleS3) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{Buckets: []s3types.Bucket{{Name: awssdk.String("pii-archive")}}}, nil
}

func (lifecycleS3) GetBucketLifecycleConfiguration(context.Context, *s3.GetBucketLifecycleConfigurationInput, ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	return &s3.GetBucketLifecycleConfigurationOutput{Rules: []s3types.LifecycleRule{{
		ID:         awssdk.String("expire-after-90d"),
		Expiration: &s3types.LifecycleExpiration{Days: awssdk.Int32(90)},
	}}}, nil
}

func TestCollectS3Lifecycle(t *testing.T) {
	c := &aws.Collector{}
	aws.WithS3(lifecycleS3{})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "s3_lifecycle"})
	require.NoError(t, err)
	buckets := out.(map[string]any)["buckets"].([]map[string]any)
	require.Len(t, buckets, 1)
	lc := buckets[0]["lifecycle"].(map[string]any)
	assert.Equal(t, true, lc["enabled"])
	rules := lc["rules"].([]map[string]any)
	require.Len(t, rules, 1)
	assert.Equal(t, "expire-after-90d", rules[0]["id"])
	assert.Equal(t, int32(90), rules[0]["expiration_days"])
}
