package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectCloudTrailEventSelectors reports each trail's event selectors. Shape:
//
//	{ fetched_at, trails: [ { name, event_selectors: [
//	    { include_management_events, read_write_type,
//	      data_resources: [ { type, values } ] } ] } ] }
//
// This backs the cloudtrail_event_selectors evidence type the FedRAMP AU-2,
// NIST-CSF, and PCI-DSS 10 logging controls read (they require management
// events and data-event coverage on the trail).
func (c *Collector) collectCloudTrailEventSelectors(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	trailsOut, err := c.cloudtrail.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, wrapErr("describing CloudTrail trails", err)
	}
	trails := make([]map[string]any, 0, len(trailsOut.TrailList))
	for _, t := range trailsOut.TrailList {
		name := aws.ToString(t.Name)
		sel, err := c.cloudtrail.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{TrailName: t.TrailARN})
		if err != nil {
			return nil, wrapErr("getting event selectors for trail "+name, err)
		}
		selectors := make([]map[string]any, 0, len(sel.EventSelectors))
		for _, s := range sel.EventSelectors {
			dataResources := make([]map[string]any, 0, len(s.DataResources))
			for _, dr := range s.DataResources {
				dataResources = append(dataResources, map[string]any{
					"type":   aws.ToString(dr.Type),
					"values": dr.Values,
				})
			}
			selectors = append(selectors, map[string]any{
				"include_management_events": aws.ToBool(s.IncludeManagementEvents),
				"read_write_type":           string(s.ReadWriteType),
				"data_resources":            dataResources,
			})
		}
		trails = append(trails, map[string]any{
			"name":            name,
			"event_selectors": selectors,
		})
	}
	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"trails":     trails,
	}, nil
}
