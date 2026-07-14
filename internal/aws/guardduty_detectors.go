package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectGuardDutyDetectors reports GuardDuty detector status plus unresolved
// HIGH-severity findings. Shape:
//
//	{ fetched_at,
//	  regions_with_ephi:      [ region ],
//	  regions_with_workloads: [ region ],
//	  detectors:              [ { id, region, status } ],
//	  high_severity_findings: [ { id, region, resource, age_days, severity } ] }
//
// This backs the guardduty_detectors evidence type read by HIPAA
// §164.308(a)(5) (malware protection) and ISO 27001 A.5.7 (threat
// intelligence). The two controls read the same detectors + high_severity_findings
// shape but diverge on the region key — HIPAA reads regions_with_ephi, ISO
// reads regions_with_workloads — so the collector emits both.
//
// NOTE: AWS does not expose which regions hold ePHI / production workloads (that
// is an operator classification), and the plugin is single-region. The
// collector treats the region under audit as in-scope for both keys, so the
// per-region deny fails closed when the assessed region has no ENABLED detector
// — matching how guardduty_status reports active_regions.
func (c *Collector) collectGuardDutyDetectors(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	detectors, err := c.guardDutyDetectors(ctx)
	if err != nil {
		return nil, err
	}
	findings, err := c.guardDutyHighSeverityFindings(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"fetched_at":             time.Now().UTC().Format(time.RFC3339),
		"regions_with_ephi":      []string{c.region},
		"regions_with_workloads": []string{c.region},
		"detectors":              detectors,
		"high_severity_findings": findings,
	}, nil
}

// guardDutyHighSeverityFindings returns unresolved HIGH-severity (severity >= 7)
// findings across every detector in the region.
func (c *Collector) guardDutyHighSeverityFindings(ctx context.Context) ([]map[string]any, error) {
	out := make([]map[string]any, 0)
	pager := guardduty.NewListDetectorsPaginator(c.guardduty, &guardduty.ListDetectorsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("listing GuardDuty detectors", err)
		}
		for _, id := range page.DetectorIds {
			f, err := c.detectorHighSeverityFindings(ctx, id)
			if err != nil {
				return nil, err
			}
			out = append(out, f...)
		}
	}
	return out, nil
}

func (c *Collector) detectorHighSeverityFindings(ctx context.Context, detectorID string) ([]map[string]any, error) {
	criteria := &gdtypes.FindingCriteria{Criterion: map[string]gdtypes.Condition{
		"severity":         {GreaterThanOrEqual: aws.Int64(7)},
		"service.archived": {Equals: []string{"false"}},
	}}
	ids := make([]string, 0)
	pager := guardduty.NewListFindingsPaginator(c.guardduty, &guardduty.ListFindingsInput{
		DetectorId:      aws.String(detectorID),
		FindingCriteria: criteria,
	})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("listing GuardDuty findings", err)
		}
		ids = append(ids, page.FindingIds...)
	}

	out := make([]map[string]any, 0, len(ids))
	// GetFindings accepts at most 50 finding ids per call.
	for start := 0; start < len(ids); start += 50 {
		end := start + 50
		if end > len(ids) {
			end = len(ids)
		}
		res, err := c.guardduty.GetFindings(ctx, &guardduty.GetFindingsInput{
			DetectorId: aws.String(detectorID),
			FindingIds: ids[start:end],
		})
		if err != nil {
			return nil, wrapErr("getting GuardDuty findings", err)
		}
		for _, f := range res.Findings {
			out = append(out, map[string]any{
				"id":       aws.ToString(f.Id),
				"region":   aws.ToString(f.Region),
				"resource": findingResourceType(f),
				"age_days": findingAgeDays(f),
				"severity": aws.ToFloat64(f.Severity),
			})
		}
	}
	return out, nil
}

func findingResourceType(f gdtypes.Finding) string {
	if f.Resource == nil {
		return ""
	}
	return aws.ToString(f.Resource.ResourceType)
}

// findingAgeDays returns whole days since the finding was last updated (falling
// back to creation time), or 0 when no parseable timestamp is present.
func findingAgeDays(f gdtypes.Finding) int {
	s := aws.ToString(f.UpdatedAt)
	if s == "" {
		s = aws.ToString(f.CreatedAt)
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t, err = time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return 0
		}
	}
	return int(time.Since(t).Hours() / 24)
}
