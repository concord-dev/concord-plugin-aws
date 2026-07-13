package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspectortypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectInspectorFindings reports Amazon Inspector enablement and the count of
// unresolved critical/high findings. Shape:
//
//	{ fetched_at, active_regions: [ region ],
//	  scanners: [ { region, inspector_enabled } ],
//	  findings: { critical_unresolved, high_unresolved } }
//
// This backs the inspector_findings evidence type the FedRAMP RA-5
// vulnerability-monitoring control reads. Single-region.
func (c *Collector) collectInspectorFindings(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	enabled := c.inspectorEnabled(ctx)
	critical, high, err := c.inspectorSeverityCounts(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"fetched_at":     time.Now().UTC().Format(time.RFC3339),
		"active_regions": []string{c.region},
		"scanners":       []map[string]any{{"region": c.region, "inspector_enabled": enabled}},
		"findings": map[string]any{
			"critical_unresolved": critical,
			"high_unresolved":     high,
		},
	}, nil
}

// inspectorSeverityCounts counts ACTIVE findings at CRITICAL and HIGH severity.
func (c *Collector) inspectorSeverityCounts(ctx context.Context) (int, int, error) {
	active := &inspectortypes.FilterCriteria{
		FindingStatus: []inspectortypes.StringFilter{{
			Comparison: inspectortypes.StringComparisonEquals,
			Value:      aws.String("ACTIVE"),
		}},
	}
	critical, err := c.countFindings(ctx, active, inspectortypes.SeverityCritical)
	if err != nil {
		return 0, 0, err
	}
	high, err := c.countFindings(ctx, active, inspectortypes.SeverityHigh)
	if err != nil {
		return 0, 0, err
	}
	return critical, high, nil
}

func (c *Collector) countFindings(ctx context.Context, base *inspectortypes.FilterCriteria, sev inspectortypes.Severity) (int, error) {
	filter := *base
	filter.Severity = []inspectortypes.StringFilter{{
		Comparison: inspectortypes.StringComparisonEquals,
		Value:      aws.String(string(sev)),
	}}
	count := 0
	pager := inspector2.NewListFindingsPaginator(c.inspector, &inspector2.ListFindingsInput{FilterCriteria: &filter})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return 0, wrapErr("listing Inspector findings", err)
		}
		count += len(page.Findings)
	}
	return count, nil
}
