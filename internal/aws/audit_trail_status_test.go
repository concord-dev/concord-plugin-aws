package aws_test

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
)

// publicBucketS3 reuses fakeS3 but reports a Public Access Block that does not
// fully block public access, so the trail bucket reads as public.
type publicBucketS3 struct{ fakeS3 }

func (publicBucketS3) GetPublicAccessBlock(_ context.Context, _ *s3.GetPublicAccessBlockInput, _ ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
		BlockPublicAcls: awssdk.Bool(false),
	}}, nil
}

func TestCollectAuditTrailStatus(t *testing.T) {
	c := &aws.Collector{}
	aws.WithCloudTrail(fakeCloudTrail{
		trails: []cttypes.Trail{{
			Name:                       awssdk.String("org-trail"),
			TrailARN:                   awssdk.String("arn:aws:cloudtrail:us-east-1:1:trail/org-trail"),
			IsMultiRegionTrail:         awssdk.Bool(true),
			LogFileValidationEnabled:   awssdk.Bool(true),
			KmsKeyId:                   awssdk.String("arn:aws:kms:us-east-1:1:key/abc"),
			S3BucketName:               awssdk.String("audit-logs"),
			IncludeGlobalServiceEvents: awssdk.Bool(true),
		}},
		selectors: []cttypes.EventSelector{{IncludeManagementEvents: awssdk.Bool(true)}},
		logging:   true,
	})(c)
	aws.WithS3(publicBucketS3{})(c)
	aws.WithCloudWatchLogs(fakeCWLogs{
		groups: []cwltypes.LogGroup{{
			LogGroupName:    awssdk.String("/aws/prod/api"),
			Arn:             awssdk.String("arn:aws:logs:us-east-1:1:log-group:/aws/prod/api"),
			RetentionInDays: awssdk.Int32(730),
		}},
		tags: map[string]string{"production": "true"},
	})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "audit_trail_status"})
	require.NoError(t, err)
	m := out.(map[string]any)

	trails := m["cloudtrail"].(map[string]any)["trails"].([]map[string]any)
	require.Len(t, trails, 1)
	tr := trails[0]
	assert.Equal(t, "org-trail", tr["name"])
	assert.Equal(t, true, tr["is_logging"])
	assert.Equal(t, true, tr["is_multi_region_trail"])
	assert.Equal(t, true, tr["log_file_validation_enabled"])
	assert.Equal(t, "arn:aws:kms:us-east-1:1:key/abc", tr["kms_key_id"])
	assert.Equal(t, true, tr["s3_bucket_is_public"], "non-blocking PAB reads as public")
	assert.Equal(t, true, tr["include_global_service_events"])
	assert.Equal(t, true, tr["include_management_events"])

	groups := m["log_groups"].([]map[string]any)
	require.Len(t, groups, 1)
	assert.Equal(t, "/aws/prod/api", groups[0]["name"])
	assert.Equal(t, true, groups[0]["is_production"])
	assert.Equal(t, int32(730), groups[0]["retention_in_days"])
}
