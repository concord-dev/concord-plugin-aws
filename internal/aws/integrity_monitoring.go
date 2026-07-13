package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectIntegrityMonitoring reports the two controls that give AWS its
// file/config-integrity signal: CloudTrail log-file validation and AWS Config
// recording. Shape:
//
//	{ fetched_at,
//	  trails: [ { name, is_multi_region, is_logging, log_file_validation_enabled } ],
//	  config_recorders: [ { name, region, recording, all_supported } ] }
//
// This backs the integrity_monitoring evidence type the FedRAMP SI-7 control
// reads (log-file validation + config recording stand in for integrity
// monitoring on AWS).
func (c *Collector) collectIntegrityMonitoring(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	trailsOut, err := c.cloudtrail.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, wrapErr("describing CloudTrail trails", err)
	}
	trails := make([]map[string]any, 0, len(trailsOut.TrailList))
	for _, t := range trailsOut.TrailList {
		name := aws.ToString(t.Name)
		logging := false
		if st, err := c.cloudtrail.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: t.TrailARN}); err == nil {
			logging = aws.ToBool(st.IsLogging)
		}
		trails = append(trails, map[string]any{
			"name":                        name,
			"is_multi_region":             aws.ToBool(t.IsMultiRegionTrail),
			"is_logging":                  logging,
			"log_file_validation_enabled": aws.ToBool(t.LogFileValidationEnabled),
		})
	}
	return map[string]any{
		"fetched_at":       time.Now().UTC().Format(time.RFC3339),
		"trails":           trails,
		"config_recorders": c.configRecorders(ctx),
	}, nil
}
