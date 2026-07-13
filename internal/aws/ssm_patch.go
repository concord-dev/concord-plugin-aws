package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectSSMPatchCompliance reports SSM patch state per managed instance. Shape:
//
//	{ fetched_at, instances: [ { instance_id, patch_group, compliance_status,
//	    missing_critical_count, missing_security_count } ] }
//
// This backs the ssm_patch_compliance evidence type the FedRAMP SI-2, NIST-CSF
// PR.PS-02, and PCI-DSS 6.2 patch-management controls read. compliance_status
// is derived: NON_COMPLIANT when any critical or security patch is
// non-compliant, else COMPLIANT.
//
// NOTE: the packs' fixtures also carry oldest_missing_critical_age_days, which
// SSM's DescribeInstancePatchStates does not expose; the collector omits it, so
// that specific age-based refinement in a control is not yet backed (the
// primary compliance-status and missing-count checks are).
func (c *Collector) collectSSMPatchCompliance(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	instances := make([]map[string]any, 0)
	pager := ssm.NewDescribeInstancePatchStatesPaginator(c.ssm, &ssm.DescribeInstancePatchStatesInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("describing SSM instance patch states", err)
		}
		for _, s := range page.InstancePatchStates {
			critical := aws.ToInt32(s.CriticalNonCompliantCount)
			security := aws.ToInt32(s.SecurityNonCompliantCount)
			status := "COMPLIANT"
			if critical > 0 || security > 0 {
				status = "NON_COMPLIANT"
			}
			instances = append(instances, map[string]any{
				"instance_id":            aws.ToString(s.InstanceId),
				"patch_group":            aws.ToString(s.PatchGroup),
				"compliance_status":      status,
				"missing_critical_count": critical,
				"missing_security_count": security,
			})
		}
	}
	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"instances":  instances,
	}, nil
}
