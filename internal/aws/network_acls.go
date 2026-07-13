package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectNetworkACLs reports every network ACL with its rule entries. Shape:
//
//	{ fetched_at, acls: [ { id, vpc_id, is_default, entries: [
//	    { rule_number, egress, protocol, from_port, to_port, cidr, action } ] } ] }
//
// This backs the network_acls evidence type the PCI-DSS network-segmentation
// controls read. Protocol numbers are mapped to names (-1 -> all, 6 -> tcp,
// 17 -> udp, 1 -> icmp) to match how the controls express rules.
func (c *Collector) collectNetworkACLs(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	acls := make([]map[string]any, 0)
	pager := ec2.NewDescribeNetworkAclsPaginator(c.ec2, &ec2.DescribeNetworkAclsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("describing network ACLs", err)
		}
		for _, a := range page.NetworkAcls {
			entries := make([]map[string]any, 0, len(a.Entries))
			for _, e := range a.Entries {
				entry := map[string]any{
					"rule_number": aws.ToInt32(e.RuleNumber),
					"egress":      aws.ToBool(e.Egress),
					"protocol":    naclProtocol(aws.ToString(e.Protocol)),
					"cidr":        aws.ToString(e.CidrBlock),
					"action":      string(e.RuleAction),
				}
				if e.PortRange != nil {
					entry["from_port"] = aws.ToInt32(e.PortRange.From)
					entry["to_port"] = aws.ToInt32(e.PortRange.To)
				}
				entries = append(entries, entry)
			}
			acls = append(acls, map[string]any{
				"id":         aws.ToString(a.NetworkAclId),
				"vpc_id":     aws.ToString(a.VpcId),
				"is_default": aws.ToBool(a.IsDefault),
				"entries":    entries,
			})
		}
	}
	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"acls":       acls,
	}, nil
}

// naclProtocol maps an IANA protocol number (as AWS returns it) to the name the
// controls use; unknown numbers pass through unchanged.
func naclProtocol(p string) string {
	switch p {
	case "-1":
		return "all"
	case "6":
		return "tcp"
	case "17":
		return "udp"
	case "1":
		return "icmp"
	default:
		return p
	}
}
