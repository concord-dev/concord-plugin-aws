package aws_test

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
)

type fakeELBv2 struct {
	lbs       []elbv2types.LoadBalancer
	listeners []elbv2types.Listener
	tags      []elbv2types.Tag
}

func (f fakeELBv2) DescribeLoadBalancers(context.Context, *elbv2.DescribeLoadBalancersInput, ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error) {
	return &elbv2.DescribeLoadBalancersOutput{LoadBalancers: f.lbs}, nil
}

func (f fakeELBv2) DescribeListeners(context.Context, *elbv2.DescribeListenersInput, ...func(*elbv2.Options)) (*elbv2.DescribeListenersOutput, error) {
	return &elbv2.DescribeListenersOutput{Listeners: f.listeners}, nil
}

func (f fakeELBv2) DescribeTags(context.Context, *elbv2.DescribeTagsInput, ...func(*elbv2.Options)) (*elbv2.DescribeTagsOutput, error) {
	return &elbv2.DescribeTagsOutput{TagDescriptions: []elbv2types.TagDescription{{Tags: f.tags}}}, nil
}

func TestCollectTLSEndpoints(t *testing.T) {
	c := &aws.Collector{}
	aws.WithS3(policyS3{})(c) // one bucket with a TLS-deny policy (from network_test.go)
	aws.WithELBv2(fakeELBv2{
		lbs:       []elbv2types.LoadBalancer{{LoadBalancerName: awssdk.String("phi-api-alb"), LoadBalancerArn: awssdk.String("arn:lb")}},
		listeners: []elbv2types.Listener{{Port: awssdk.Int32(443), Protocol: elbv2types.ProtocolEnumHttps, SslPolicy: awssdk.String("ELBSecurityPolicy-TLS13-1-2-2021-06")}},
		tags:      []elbv2types.Tag{{Key: awssdk.String("ephi"), Value: awssdk.String("true")}},
	})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "aws_tls_endpoints"})
	require.NoError(t, err)
	m := out.(map[string]any)

	buckets := m["buckets"].([]map[string]any)
	require.Len(t, buckets, 1)
	assert.Equal(t, "phi-records", buckets[0]["name"])

	lbs := m["load_balancers"].([]map[string]any)
	require.Len(t, lbs, 1)
	assert.Equal(t, "phi-api-alb", lbs[0]["name"])
	assert.Equal(t, "true", lbs[0]["tags"].(map[string]any)["ephi"])
	listeners := lbs[0]["listeners"].([]map[string]any)
	require.Len(t, listeners, 1)
	assert.Equal(t, int32(443), listeners[0]["port"])
	assert.Equal(t, "HTTPS", listeners[0]["protocol"])
	assert.Equal(t, "ELBSecurityPolicy-TLS13-1-2-2021-06", listeners[0]["ssl_policy"])
}
