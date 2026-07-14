package aws_test

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
)

func TestCollectGuardDutyDetectors(t *testing.T) {
	c := &aws.Collector{}
	aws.WithGuardDuty(fakeGuardDuty{
		ids:        []string{"det-1"},
		status:     gdtypes.DetectorStatusEnabled,
		findingIDs: []string{"f-1"},
		findings: []gdtypes.Finding{{
			Id:        awssdk.String("f-1"),
			Region:    awssdk.String("us-east-1"),
			Severity:  awssdk.Float64(8.0),
			UpdatedAt: awssdk.String("2026-06-01T00:00:00Z"),
			Resource:  &gdtypes.Resource{ResourceType: awssdk.String("Instance")},
		}},
	})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "guardduty_detectors"})
	require.NoError(t, err)
	m := out.(map[string]any)

	// Both region keys are emitted so HIPAA (regions_with_ephi) and ISO
	// (regions_with_workloads) each find the key their rego reads.
	assert.NotEmpty(t, m["regions_with_ephi"])
	assert.NotEmpty(t, m["regions_with_workloads"])

	dets := m["detectors"].([]map[string]any)
	require.Len(t, dets, 1)
	assert.Equal(t, "det-1", dets[0]["id"])
	assert.Equal(t, "ENABLED", dets[0]["status"])

	findings := m["high_severity_findings"].([]map[string]any)
	require.Len(t, findings, 1)
	assert.Equal(t, "f-1", findings[0]["id"])
	assert.Equal(t, "us-east-1", findings[0]["region"])
	assert.Equal(t, "Instance", findings[0]["resource"])
	assert.Greater(t, findings[0]["age_days"].(int), 0, "a June 2026 finding is aged from collection time")
}
