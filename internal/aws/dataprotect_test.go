package aws_test

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
)

type fakeKMS struct {
	keys     []kmstypes.KeyListEntry
	manager  kmstypes.KeyManagerType
	state    kmstypes.KeyState
	rotation bool
	tags     []kmstypes.Tag
}

func (f fakeKMS) ListKeys(context.Context, *kms.ListKeysInput, ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	return &kms.ListKeysOutput{Keys: f.keys}, nil
}

func (f fakeKMS) DescribeKey(_ context.Context, in *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{
		KeyId:      in.KeyId,
		Arn:        awssdk.String("arn:aws:kms:us-east-1:123456789012:key/" + awssdk.ToString(in.KeyId)),
		KeyManager: f.manager,
		KeyState:   f.state,
	}}, nil
}

func (f fakeKMS) GetKeyRotationStatus(context.Context, *kms.GetKeyRotationStatusInput, ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
	return &kms.GetKeyRotationStatusOutput{KeyRotationEnabled: f.rotation, RotationPeriodInDays: awssdk.Int32(365)}, nil
}

func (f fakeKMS) ListResourceTags(context.Context, *kms.ListResourceTagsInput, ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error) {
	return &kms.ListResourceTagsOutput{Tags: f.tags}, nil
}

func TestCollectKMSKeys(t *testing.T) {
	c := &aws.Collector{}
	aws.WithKMS(fakeKMS{
		keys:     []kmstypes.KeyListEntry{{KeyId: awssdk.String("abc-pci")}},
		manager:  kmstypes.KeyManagerTypeCustomer,
		state:    kmstypes.KeyStateEnabled,
		rotation: true,
		tags:     []kmstypes.Tag{{TagKey: awssdk.String("pci"), TagValue: awssdk.String("true")}},
	})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "kms_keys"})
	require.NoError(t, err)
	keys := out.(map[string]any)["keys"].([]map[string]any)
	require.Len(t, keys, 1)
	assert.Equal(t, "Enabled", keys[0]["key_state"])
	assert.Equal(t, true, keys[0]["rotation_enabled"])
	assert.Equal(t, int32(365), keys[0]["rotation_period_days"])
	assert.Equal(t, "true", keys[0]["tags"].(map[string]any)["pci"])
}

func TestCollectKMSKeys_SkipsAWSManaged(t *testing.T) {
	c := &aws.Collector{}
	aws.WithKMS(fakeKMS{
		keys:    []kmstypes.KeyListEntry{{KeyId: awssdk.String("aws/s3")}},
		manager: kmstypes.KeyManagerTypeAws,
	})(c)
	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "kms_keys"})
	require.NoError(t, err)
	assert.Empty(t, out.(map[string]any)["keys"], "AWS-managed keys are skipped")
}

func TestCollectNetworkACLs(t *testing.T) {
	c := &aws.Collector{}
	aws.WithEC2(fakeEC2{nacls: []ec2types.NetworkAcl{{
		NetworkAclId: awssdk.String("acl-1"),
		VpcId:        awssdk.String("vpc-1"),
		IsDefault:    awssdk.Bool(false),
		Entries: []ec2types.NetworkAclEntry{
			{RuleNumber: awssdk.Int32(200), Egress: awssdk.Bool(false), Protocol: awssdk.String("-1"),
				CidrBlock: awssdk.String("0.0.0.0/0"), RuleAction: ec2types.RuleActionDeny},
		},
	}}})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "network_acls"})
	require.NoError(t, err)
	acls := out.(map[string]any)["acls"].([]map[string]any)
	require.Len(t, acls, 1)
	entries := acls[0]["entries"].([]map[string]any)
	require.Len(t, entries, 1)
	assert.Equal(t, "all", entries[0]["protocol"], "protocol -1 maps to all")
	assert.Equal(t, "deny", entries[0]["action"])
}

// integrityS3 returns one bucket with versioning + Object Lock enabled.
type integrityS3 struct{ fakeS3 }

func (integrityS3) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{Buckets: []s3types.Bucket{{Name: awssdk.String("phi-records")}}}, nil
}

func (integrityS3) GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	return &s3.GetBucketVersioningOutput{Status: s3types.BucketVersioningStatusEnabled, MFADelete: s3types.MFADeleteStatusEnabled}, nil
}

func (integrityS3) GetObjectLockConfiguration(context.Context, *s3.GetObjectLockConfigurationInput, ...func(*s3.Options)) (*s3.GetObjectLockConfigurationOutput, error) {
	return &s3.GetObjectLockConfigurationOutput{ObjectLockConfiguration: &s3types.ObjectLockConfiguration{
		ObjectLockEnabled: s3types.ObjectLockEnabledEnabled,
		Rule:              &s3types.ObjectLockRule{DefaultRetention: &s3types.DefaultRetention{Mode: s3types.ObjectLockRetentionModeCompliance, Days: awssdk.Int32(2557)}},
	}}, nil
}

func TestCollectS3BucketIntegrity(t *testing.T) {
	c := &aws.Collector{}
	aws.WithS3(integrityS3{})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "s3_bucket_integrity"})
	require.NoError(t, err)
	buckets := out.(map[string]any)["buckets"].([]map[string]any)
	require.Len(t, buckets, 1)
	assert.Equal(t, true, buckets[0]["versioning"].(map[string]any)["enabled"])
	assert.Equal(t, "Enabled", buckets[0]["versioning"].(map[string]any)["mfa_delete"])
	lock := buckets[0]["object_lock"].(map[string]any)
	assert.Equal(t, true, lock["enabled"])
	assert.Equal(t, "COMPLIANCE", lock["mode"])
}
