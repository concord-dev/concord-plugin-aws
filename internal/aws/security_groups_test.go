package aws_test

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
)

func TestCollectSecurityGroups(t *testing.T) {
	c := &aws.Collector{}
	aws.WithEC2(fakeEC2{sgs: []ec2types.SecurityGroup{
		{
			GroupId:     awssdk.String("sg-public-alb"),
			GroupName:   awssdk.String("public-alb"),
			Description: awssdk.String("Internet-facing ALB"),
			Tags:        []ec2types.Tag{{Key: awssdk.String("scope"), Value: awssdk.String("public")}},
			IpPermissions: []ec2types.IpPermission{{
				IpProtocol: awssdk.String("tcp"),
				FromPort:   awssdk.Int32(443),
				ToPort:     awssdk.Int32(443),
				IpRanges:   []ec2types.IpRange{{CidrIp: awssdk.String("0.0.0.0/0")}},
			}},
		},
		{
			// no scope tag -> scope omitted so fail-closed controls surface it
			GroupId:     awssdk.String("sg-unclassified"),
			Description: awssdk.String("no scope tag"),
		},
	}})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "security_groups"})
	require.NoError(t, err)
	m := out.(map[string]any)
	require.NotEmpty(t, m["fetched_at"])

	groups := m["groups"].([]map[string]any)
	require.Len(t, groups, 2)

	assert.Equal(t, "sg-public-alb", groups[0]["id"])
	assert.Equal(t, "public", groups[0]["scope"])
	ingress := groups[0]["ingress_rules"].([]map[string]any)
	require.Len(t, ingress, 1)
	assert.Equal(t, "0.0.0.0/0", ingress[0]["cidr"])
	assert.Equal(t, int32(443), ingress[0]["from_port"])
	assert.Equal(t, "tcp", ingress[0]["protocol"])

	// unclassified group carries no scope key
	_, hasScope := groups[1]["scope"]
	assert.False(t, hasScope, "a group with no scope tag must omit scope (fail-closed)")
}
