package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectConfigRecorderStatus reports AWS Config recorder coverage in the
// collector's region. Shape:
//
//	{ fetched_at, active_regions: [ region ],
//	  recorders: [ { name, region, recording, all_supported } ] }
//
// This backs the config_recorder_status evidence type the FedRAMP CA-7/CM-2,
// ISO 27001 A.5.23, NIST-CSF PR.PS-01, and PCI-DSS 2.2 continuous-monitoring
// controls read (they require an all-supported recorder that is actively
// recording). Note: the collector is single-region, so active_regions reports
// the region under audit.
func (c *Collector) collectConfigRecorderStatus(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	recOut, err := c.config.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		return nil, wrapErr("describing AWS Config recorders", err)
	}
	statusOut, err := c.config.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{})
	if err != nil {
		return nil, wrapErr("describing AWS Config recorder status", err)
	}
	recording := map[string]bool{}
	for _, s := range statusOut.ConfigurationRecordersStatus {
		recording[aws.ToString(s.Name)] = s.Recording
	}

	recorders := make([]map[string]any, 0, len(recOut.ConfigurationRecorders))
	for _, r := range recOut.ConfigurationRecorders {
		name := aws.ToString(r.Name)
		allSupported := false
		if r.RecordingGroup != nil {
			allSupported = r.RecordingGroup.AllSupported
		}
		recorders = append(recorders, map[string]any{
			"name":          name,
			"region":        c.region,
			"recording":     recording[name],
			"all_supported": allSupported,
		})
	}
	return map[string]any{
		"fetched_at":     time.Now().UTC().Format(time.RFC3339),
		"active_regions": []string{c.region},
		"recorders":      recorders,
	}, nil
}
