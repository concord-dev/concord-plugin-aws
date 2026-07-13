package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectEC2Inventory reports EC2 instances with tags, plus whether AWS Config
// is actively recording (so an inventory control can require config-backed
// asset tracking). Shape:
//
//	{ fetched_at, config_recorder_active, instances: [ { id, tags } ] }
//
// This backs the ec2_inventory evidence type the NIST-CSF ID.AM-01
// asset-inventory control reads.
func (c *Collector) collectEC2Inventory(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	instances := make([]map[string]any, 0)
	pager := ec2.NewDescribeInstancesPaginator(c.ec2, &ec2.DescribeInstancesInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("describing EC2 instances", err)
		}
		for _, r := range page.Reservations {
			for _, inst := range r.Instances {
				instances = append(instances, map[string]any{
					"id":   aws.ToString(inst.InstanceId),
					"tags": ec2Tags(inst.Tags),
				})
			}
		}
	}
	return map[string]any{
		"fetched_at":             time.Now().UTC().Format(time.RFC3339),
		"config_recorder_active": c.configRecorderActive(ctx),
		"instances":              instances,
	}, nil
}

// configRecorderActive reports whether any AWS Config recorder is recording in
// the region. It is best-effort: an error (e.g. no Config permission) reports
// false rather than failing the inventory collection.
func (c *Collector) configRecorderActive(ctx context.Context) bool {
	out, err := c.config.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{})
	if err != nil {
		return false
	}
	for _, s := range out.ConfigurationRecordersStatus {
		if s.Recording {
			return true
		}
	}
	return false
}
