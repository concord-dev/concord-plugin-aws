package aws_test

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
)

// fakeCloudFront returns a fixed distribution list.
type fakeCloudFront struct {
	dists []cftypes.DistributionSummary
}

func (f fakeCloudFront) ListDistributions(context.Context, *cloudfront.ListDistributionsInput, ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
	return &cloudfront.ListDistributionsOutput{DistributionList: &cftypes.DistributionList{Items: f.dists}}, nil
}

// fakeWAFv2 reports an association for any resource ARN in associated, and the
// number of rules on that WebACL from rules (default 0).
type fakeWAFv2 struct {
	associated map[string]string // resource ARN -> WebACL ARN
	rules      map[string]int    // resource ARN -> rule count
}

func (f fakeWAFv2) GetWebACLForResource(_ context.Context, in *wafv2.GetWebACLForResourceInput, _ ...func(*wafv2.Options)) (*wafv2.GetWebACLForResourceOutput, error) {
	arn := awssdk.ToString(in.ResourceArn)
	if acl, ok := f.associated[arn]; ok {
		webACL := &waftypes.WebACL{ARN: awssdk.String(acl)}
		webACL.Rules = make([]waftypes.Rule, f.rules[arn])
		return &wafv2.GetWebACLForResourceOutput{WebACL: webACL}, nil
	}
	return &wafv2.GetWebACLForResourceOutput{}, nil
}

func TestCollectWAFCoverage(t *testing.T) {
	c := &aws.Collector{}
	aws.WithELBv2(fakeELBv2{lbs: []elbv2types.LoadBalancer{
		{LoadBalancerArn: awssdk.String("arn:alb:public"), Type: elbv2types.LoadBalancerTypeEnumApplication, Scheme: elbv2types.LoadBalancerSchemeEnumInternetFacing},
		{LoadBalancerArn: awssdk.String("arn:alb:internal"), Type: elbv2types.LoadBalancerTypeEnumApplication, Scheme: elbv2types.LoadBalancerSchemeEnumInternal},
		{LoadBalancerArn: awssdk.String("arn:nlb"), Type: elbv2types.LoadBalancerTypeEnumNetwork, Scheme: elbv2types.LoadBalancerSchemeEnumInternetFacing},
	}})(c)
	aws.WithWAFv2(fakeWAFv2{associated: map[string]string{"arn:alb:public": "arn:wafv2:public-acl"}})(c)
	aws.WithCloudFront(fakeCloudFront{dists: []cftypes.DistributionSummary{
		{ARN: awssdk.String("arn:cf:dist1"), Enabled: awssdk.Bool(true), WebACLId: awssdk.String("arn:wafv2:cdn-acl")},
	}})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "waf_coverage"})
	require.NoError(t, err)
	m := out.(map[string]any)

	resources := m["resources"].([]map[string]any)
	// Two ALBs (application-type) + one CloudFront distribution; the NLB is skipped.
	require.Len(t, resources, 3)

	byARN := map[string]map[string]any{}
	for _, r := range resources {
		byARN[r["arn"].(string)] = r
	}

	pub := byARN["arn:alb:public"]
	assert.Equal(t, "application_load_balancer", pub["type"])
	assert.Equal(t, true, pub["public_facing"])
	assert.Equal(t, true, pub["web_acl_associated"])
	assert.Equal(t, "arn:wafv2:public-acl", pub["web_acl_arn"])

	internal := byARN["arn:alb:internal"]
	assert.Equal(t, false, internal["public_facing"])
	assert.Equal(t, false, internal["web_acl_associated"])

	cf := byARN["arn:cf:dist1"]
	assert.Equal(t, "cloudfront_distribution", cf["type"])
	assert.Equal(t, true, cf["public_facing"])
	assert.Equal(t, true, cf["web_acl_associated"])
	assert.Equal(t, "arn:wafv2:cdn-acl", cf["web_acl_arn"])

	_, hasNLB := byARN["arn:nlb"]
	assert.False(t, hasNLB, "network load balancers are not WAF-associable and should be skipped")
}
