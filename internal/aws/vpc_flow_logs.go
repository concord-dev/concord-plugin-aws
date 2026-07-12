package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectVPCFlowLogs reports each VPC and whether it has an active flow log.
// Shape (both a flat flag and a detail object, so every consuming control's
// shape is satisfied):
//
//	{ fetched_at, vpcs: [ { id, region, flow_logs_enabled,
//	    flow_logs: { enabled, status, log_destination_type } } ] }
//
// This backs the vpc_flow_logs evidence type the CIS-AWS 5.2, ISO 27001 A.8.20,
// and NIST-CSF DE.CM-01 network-monitoring controls read. A VPC counts as
// enabled only when an ACTIVE flow log targets it, so a VPC with a disabled or
// errored flow log is reported as not enabled (fail closed).
func (c *Collector) collectVPCFlowLogs(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	flByVPC := map[string]ec2types.FlowLog{}
	flPager := ec2.NewDescribeFlowLogsPaginator(c.ec2, &ec2.DescribeFlowLogsInput{})
	for flPager.HasMorePages() {
		page, err := flPager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("describing VPC flow logs", err)
		}
		for _, fl := range page.FlowLogs {
			id := aws.ToString(fl.ResourceId)
			// prefer an ACTIVE flow log when a VPC has several
			if cur, ok := flByVPC[id]; !ok || aws.ToString(cur.FlowLogStatus) != "ACTIVE" {
				flByVPC[id] = fl
			}
		}
	}

	vpcs := make([]map[string]any, 0)
	vpcPager := ec2.NewDescribeVpcsPaginator(c.ec2, &ec2.DescribeVpcsInput{})
	for vpcPager.HasMorePages() {
		page, err := vpcPager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("describing VPCs", err)
		}
		for _, v := range page.Vpcs {
			id := aws.ToString(v.VpcId)
			fl, hasFlowLog := flByVPC[id]
			enabled := hasFlowLog && aws.ToString(fl.FlowLogStatus) == "ACTIVE"
			vpcs = append(vpcs, map[string]any{
				"id":                id,
				"region":            c.region,
				"flow_logs_enabled": enabled,
				"flow_logs": map[string]any{
					"enabled":              enabled,
					"status":               aws.ToString(fl.FlowLogStatus),
					"log_destination_type": string(fl.LogDestinationType),
				},
			})
		}
	}
	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"vpcs":       vpcs,
	}, nil
}
