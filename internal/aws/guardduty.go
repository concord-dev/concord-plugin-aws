package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectGuardDutyStatus reports GuardDuty detector status in the collector's
// region. Shape:
//
//	{ fetched_at, active_regions: [ region ],
//	  guardduty_detectors: [ { region, status } ] }
//
// This backs the guardduty_status evidence type the FedRAMP SI-4, NIST-CSF
// DE.CM-09, and PCI-DSS 11.4 intrusion-detection controls read (they require an
// ENABLED detector in every active region). Single-region: active_regions
// reports the region under audit.
func (c *Collector) collectGuardDutyStatus(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	detectors, err := c.guardDutyDetectors(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"fetched_at":          time.Now().UTC().Format(time.RFC3339),
		"active_regions":      []string{c.region},
		"guardduty_detectors": detectors,
	}, nil
}

// guardDutyDetectors lists GuardDuty detectors in the region with their status.
// Shared by guardduty_status and anti_malware_status.
func (c *Collector) guardDutyDetectors(ctx context.Context) ([]map[string]any, error) {
	detectors := make([]map[string]any, 0)
	pager := guardduty.NewListDetectorsPaginator(c.guardduty, &guardduty.ListDetectorsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("listing GuardDuty detectors", err)
		}
		for _, id := range page.DetectorIds {
			det, err := c.guardduty.GetDetector(ctx, &guardduty.GetDetectorInput{DetectorId: aws.String(id)})
			if err != nil {
				return nil, wrapErr("getting GuardDuty detector "+id, err)
			}
			detectors = append(detectors, map[string]any{
				"id":     id,
				"region": c.region,
				"status": string(det.Status),
			})
		}
	}
	return detectors, nil
}
