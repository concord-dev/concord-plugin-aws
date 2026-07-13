package aws_test

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	cfgtypes4 "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspectortypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
)

type fakeInspector struct{ enabled inspectortypes.Status }

func (f fakeInspector) BatchGetAccountStatus(context.Context, *inspector2.BatchGetAccountStatusInput, ...func(*inspector2.Options)) (*inspector2.BatchGetAccountStatusOutput, error) {
	return &inspector2.BatchGetAccountStatusOutput{Accounts: []inspectortypes.AccountState{
		{State: &inspectortypes.State{Status: f.enabled}},
	}}, nil
}

func TestCollectAntiMalwareStatus(t *testing.T) {
	c := &aws.Collector{}
	aws.WithGuardDuty(fakeGuardDuty{ids: []string{"det-1"}, status: gdtypes.DetectorStatusEnabled})(c)
	aws.WithInspector2(fakeInspector{enabled: inspectortypes.StatusEnabled})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "anti_malware_status"})
	require.NoError(t, err)
	m := out.(map[string]any)
	assert.Equal(t, true, m["inspector_account_enabled"])
	dets := m["guardduty_detectors"].([]map[string]any)
	require.Len(t, dets, 1)
	assert.Equal(t, "ENABLED", dets[0]["status"])
}

func TestCollectIntegrityMonitoring(t *testing.T) {
	c := &aws.Collector{}
	aws.WithCloudTrail(fakeCloudTrail{
		trails:  []cttypes.Trail{{Name: awssdk.String("org-trail"), TrailARN: awssdk.String("arn:t"), IsMultiRegionTrail: awssdk.Bool(true), LogFileValidationEnabled: awssdk.Bool(true)}},
		logging: true,
	})(c)
	aws.WithConfig(fakeConfig{
		recorders: []cfgtypes4.ConfigurationRecorder{{Name: awssdk.String("default"), RecordingGroup: &cfgtypes4.RecordingGroup{AllSupported: true}}},
		status:    []cfgtypes4.ConfigurationRecorderStatus{{Name: awssdk.String("default"), Recording: true}},
	})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "integrity_monitoring"})
	require.NoError(t, err)
	m := out.(map[string]any)
	trails := m["trails"].([]map[string]any)
	require.Len(t, trails, 1)
	assert.Equal(t, true, trails[0]["is_logging"])
	assert.Equal(t, true, trails[0]["log_file_validation_enabled"])
	assert.Len(t, m["config_recorders"].([]map[string]any), 1)
}
