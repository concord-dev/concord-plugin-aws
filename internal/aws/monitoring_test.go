package aws_test

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
)

type fakeGuardDuty struct {
	ids        []string
	status     gdtypes.DetectorStatus
	findingIDs []string
	findings   []gdtypes.Finding
}

func (f fakeGuardDuty) ListDetectors(context.Context, *guardduty.ListDetectorsInput, ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
	return &guardduty.ListDetectorsOutput{DetectorIds: f.ids}, nil
}

func (f fakeGuardDuty) GetDetector(context.Context, *guardduty.GetDetectorInput, ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error) {
	return &guardduty.GetDetectorOutput{Status: f.status}, nil
}

func (f fakeGuardDuty) ListFindings(context.Context, *guardduty.ListFindingsInput, ...func(*guardduty.Options)) (*guardduty.ListFindingsOutput, error) {
	return &guardduty.ListFindingsOutput{FindingIds: f.findingIDs}, nil
}

func (f fakeGuardDuty) GetFindings(context.Context, *guardduty.GetFindingsInput, ...func(*guardduty.Options)) (*guardduty.GetFindingsOutput, error) {
	return &guardduty.GetFindingsOutput{Findings: f.findings}, nil
}

func TestCollectGuardDutyStatus(t *testing.T) {
	c := &aws.Collector{}
	aws.WithGuardDuty(fakeGuardDuty{ids: []string{"det-1"}, status: gdtypes.DetectorStatusEnabled})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "guardduty_status"})
	require.NoError(t, err)
	m := out.(map[string]any)
	require.NotEmpty(t, m["fetched_at"])
	require.NotNil(t, m["active_regions"])

	dets := m["guardduty_detectors"].([]map[string]any)
	require.Len(t, dets, 1)
	assert.Equal(t, "det-1", dets[0]["id"])
	assert.Equal(t, "ENABLED", dets[0]["status"])
}

type fakeSSM struct{ states []ssmtypes.InstancePatchState }

func (f fakeSSM) DescribeInstancePatchStates(context.Context, *ssm.DescribeInstancePatchStatesInput, ...func(*ssm.Options)) (*ssm.DescribeInstancePatchStatesOutput, error) {
	return &ssm.DescribeInstancePatchStatesOutput{InstancePatchStates: f.states}, nil
}

func TestCollectSSMPatchCompliance(t *testing.T) {
	c := &aws.Collector{}
	aws.WithSSM(fakeSSM{states: []ssmtypes.InstancePatchState{
		{
			InstanceId:                awssdk.String("i-compliant"),
			PatchGroup:                awssdk.String("prod"),
			CriticalNonCompliantCount: awssdk.Int32(0),
			SecurityNonCompliantCount: awssdk.Int32(0),
		},
		{
			InstanceId:                awssdk.String("i-behind"),
			PatchGroup:                awssdk.String("prod"),
			CriticalNonCompliantCount: awssdk.Int32(3),
			SecurityNonCompliantCount: awssdk.Int32(1),
		},
	}})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "ssm_patch_compliance"})
	require.NoError(t, err)
	insts := out.(map[string]any)["instances"].([]map[string]any)
	require.Len(t, insts, 2)

	byID := map[string]map[string]any{}
	for _, in := range insts {
		byID[in["instance_id"].(string)] = in
	}
	assert.Equal(t, "COMPLIANT", byID["i-compliant"]["compliance_status"])
	assert.Equal(t, "NON_COMPLIANT", byID["i-behind"]["compliance_status"], "critical/security non-compliant derives NON_COMPLIANT")
	assert.Equal(t, int32(3), byID["i-behind"]["missing_critical_count"])
}
