package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectSecurityGroups reports every EC2 security group with its inbound and
// outbound rules flattened to one entry per CIDR, plus a scope classification
// read from the group's `scope` tag (public / private / restricted). Shape:
//
//	{ fetched_at, groups: [ { id, description, scope?, tags,
//	    ingress_rules: [ { protocol, from_port, to_port, cidr } ],
//	    egress_rules:  [ { protocol, from_port, to_port, cidr } ] } ] }
//
// This backs the security_groups evidence type the PCI-DSS and FedRAMP
// network-boundary controls read. scope is emitted only when the group carries
// a scope tag, so a control that fails closed on an unclassified group
// (`not sg.scope`) surfaces the missing classification rather than passing.
func (c *Collector) collectSecurityGroups(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	groups := make([]map[string]any, 0)
	paginator := ec2.NewDescribeSecurityGroupsPaginator(c.ec2, &ec2.DescribeSecurityGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("describing security groups", err)
		}
		for _, sg := range page.SecurityGroups {
			tags := ec2Tags(sg.Tags)
			group := map[string]any{
				"id":            aws.ToString(sg.GroupId),
				"name":          aws.ToString(sg.GroupName),
				"description":   aws.ToString(sg.Description),
				"tags":          tags,
				"ingress_rules": flattenRules(sg.IpPermissions),
				"egress_rules":  flattenRules(sg.IpPermissionsEgress),
			}
			if scope, ok := tags["scope"]; ok {
				group["scope"] = scope
			}
			groups = append(groups, group)
		}
	}
	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"groups":     groups,
	}, nil
}

// flattenRules expands each IP permission into one rule per IPv4/IPv6 CIDR,
// which is the shape the network controls evaluate (they test each cidr against
// the port range). Permissions that reference only other security groups (no
// CIDR) carry no internet exposure and are omitted.
func flattenRules(perms []ec2types.IpPermission) []map[string]any {
	rules := make([]map[string]any, 0)
	for _, p := range perms {
		protocol := aws.ToString(p.IpProtocol)
		fromPort := aws.ToInt32(p.FromPort)
		toPort := aws.ToInt32(p.ToPort)
		for _, r := range p.IpRanges {
			rules = append(rules, ruleEntry(protocol, fromPort, toPort, aws.ToString(r.CidrIp)))
		}
		for _, r := range p.Ipv6Ranges {
			rules = append(rules, ruleEntry(protocol, fromPort, toPort, aws.ToString(r.CidrIpv6)))
		}
	}
	return rules
}

func ruleEntry(protocol string, fromPort, toPort int32, cidr string) map[string]any {
	return map[string]any{
		"protocol":  protocol,
		"from_port": fromPort,
		"to_port":   toPort,
		"cidr":      cidr,
	}
}
