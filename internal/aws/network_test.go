package aws_test

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
)

// policyS3 returns one bucket with a TLS-enforcing resource policy.
type policyS3 struct{ fakeS3 }

func (policyS3) ListBuckets(_ context.Context, _ *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{Buckets: []s3types.Bucket{{Name: awssdk.String("phi-records")}}}, nil
}

func (policyS3) GetBucketPolicy(_ context.Context, _ *s3.GetBucketPolicyInput, _ ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	// S3 returns the policy as plain JSON (not URL-encoded).
	return &s3.GetBucketPolicyOutput{Policy: awssdk.String(
		`{"Statement":[{"Effect":"Deny","Action":"s3:*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`,
	)}, nil
}

func TestCollectS3BucketPolicy(t *testing.T) {
	c := &aws.Collector{}
	aws.WithS3(policyS3{})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "s3_bucket_policy"})
	require.NoError(t, err)
	m := out.(map[string]any)
	require.NotEmpty(t, m["fetched_at"])

	buckets := m["buckets"].([]map[string]any)
	require.Len(t, buckets, 1)
	assert.Equal(t, "phi-records", buckets[0]["name"])
	// the raw-JSON policy is decoded into a structured object
	policy := buckets[0]["policy"].(map[string]any)
	stmts := policy["Statement"].([]any)
	require.Len(t, stmts, 1)
	assert.Equal(t, "Deny", stmts[0].(map[string]any)["Effect"])
}

func TestCollectVPCFlowLogs(t *testing.T) {
	c := &aws.Collector{}
	aws.WithEC2(fakeEC2{
		vpcs: []ec2types.Vpc{
			{VpcId: awssdk.String("vpc-logged")},
			{VpcId: awssdk.String("vpc-dark")},
		},
		flowLogs: []ec2types.FlowLog{
			{ResourceId: awssdk.String("vpc-logged"), FlowLogStatus: awssdk.String("ACTIVE")},
			// an inactive flow log must not count as enabled
			{ResourceId: awssdk.String("vpc-dark"), FlowLogStatus: awssdk.String("INACTIVE")},
		},
	})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "vpc_flow_logs"})
	require.NoError(t, err)
	vpcs := out.(map[string]any)["vpcs"].([]map[string]any)
	require.Len(t, vpcs, 2)

	byID := map[string]map[string]any{}
	for _, v := range vpcs {
		byID[v["id"].(string)] = v
	}
	assert.Equal(t, true, byID["vpc-logged"]["flow_logs_enabled"])
	assert.Equal(t, false, byID["vpc-dark"]["flow_logs_enabled"], "inactive flow log is not enabled")
	// the nested detail object is emitted too (for controls that read it)
	assert.Equal(t, "ACTIVE", byID["vpc-logged"]["flow_logs"].(map[string]any)["status"])
	assert.Equal(t, true, byID["vpc-logged"]["flow_logs"].(map[string]any)["enabled"])
}
