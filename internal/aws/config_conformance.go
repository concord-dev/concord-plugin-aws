package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectConfigConformanceStatus reports AWS Config conformance-pack compliance,
// alongside recorder coverage. Shape:
//
//	{ fetched_at, active_regions: [ region ],
//	  recorders: [ { name, region, recording, all_supported } ],
//	  conformance_packs: [ { name, compliance_state, region } ] }
//
// This backs the config_conformance_status evidence type the FedRAMP CA-2 and
// PCI-DSS 2.2 controls read. Single-region.
func (c *Collector) collectConfigConformanceStatus(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	packsOut, err := c.config.DescribeConformancePacks(ctx, &configservice.DescribeConformancePacksInput{})
	if err != nil {
		return nil, wrapErr("describing AWS Config conformance packs", err)
	}
	names := make([]string, 0, len(packsOut.ConformancePackDetails))
	for _, p := range packsOut.ConformancePackDetails {
		names = append(names, aws.ToString(p.ConformancePackName))
	}
	compliance := map[string]string{}
	if len(names) > 0 {
		sum, err := c.config.GetConformancePackComplianceSummary(ctx, &configservice.GetConformancePackComplianceSummaryInput{ConformancePackNames: names})
		if err != nil {
			return nil, wrapErr("getting conformance-pack compliance summary", err)
		}
		for _, s := range sum.ConformancePackComplianceSummaryList {
			compliance[aws.ToString(s.ConformancePackName)] = string(s.ConformancePackComplianceStatus)
		}
	}
	packs := make([]map[string]any, 0, len(names))
	for _, name := range names {
		packs = append(packs, map[string]any{
			"name":             name,
			"compliance_state": compliance[name],
			"region":           c.region,
		})
	}

	return map[string]any{
		"fetched_at":        time.Now().UTC().Format(time.RFC3339),
		"active_regions":    []string{c.region},
		"recorders":         c.configRecorders(ctx),
		"conformance_packs": packs,
	}, nil
}

// configRecorders returns the region's Config recorders (name, recording,
// all_supported); best-effort so a conformance finding does not depend on it.
func (c *Collector) configRecorders(ctx context.Context) []map[string]any {
	out := make([]map[string]any, 0)
	recOut, err := c.config.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		return out
	}
	statusOut, err := c.config.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{})
	recording := map[string]bool{}
	if err == nil {
		for _, s := range statusOut.ConfigurationRecordersStatus {
			recording[aws.ToString(s.Name)] = s.Recording
		}
	}
	for _, r := range recOut.ConfigurationRecorders {
		name := aws.ToString(r.Name)
		allSupported := false
		if r.RecordingGroup != nil {
			allSupported = r.RecordingGroup.AllSupported
		}
		out = append(out, map[string]any{
			"name":          name,
			"region":        c.region,
			"recording":     recording[name],
			"all_supported": allSupported,
		})
	}
	return out
}
