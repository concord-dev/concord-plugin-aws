package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectWAFCoverage inventories public-facing web entry points and reports
// whether each has an AWS WAF WebACL associated. Shape:
//
//	{ fetched_at,
//	  resources: [ { arn, type, scheme, public_facing,
//	                 web_acl_associated, web_acl_arn } ] }
//
// It covers two entry-point classes:
//   - internet-facing Application Load Balancers (WAFv2 GetWebACLForResource
//     against the regional endpoint), and
//   - CloudFront distributions (the distribution's own WebACLId field).
//
// This backs the waf_coverage evidence type the PCI DSS 6.6 / v4.0 6.4.1-6.4.2
// web-application-firewall control reads. That control fails closed: a
// public-facing resource with no reported WebACL is treated as unprotected, so
// the collector reports web_acl_associated only when AWS explicitly returns an
// association.
func (c *Collector) collectWAFCoverage(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	resources := make([]map[string]any, 0)

	albs, err := c.wafALBs(ctx)
	if err != nil {
		return nil, err
	}
	resources = append(resources, albs...)

	dists, err := c.wafCloudFront(ctx)
	if err != nil {
		return nil, err
	}
	resources = append(resources, dists...)

	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"resources":  resources,
	}, nil
}

// wafALBs lists Application Load Balancers and resolves the WebACL associated
// with each via WAFv2. Only Application Load Balancers are WAF-associable;
// Network and Gateway Load Balancers are skipped.
func (c *Collector) wafALBs(ctx context.Context) ([]map[string]any, error) {
	out := make([]map[string]any, 0)
	pager := elbv2.NewDescribeLoadBalancersPaginator(c.elbv2, &elbv2.DescribeLoadBalancersInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("describing load balancers", err)
		}
		for _, lb := range page.LoadBalancers {
			if lb.Type != elbv2types.LoadBalancerTypeEnumApplication {
				continue
			}
			arn := aws.ToString(lb.LoadBalancerArn)
			aclArn, associated := c.webACLForResource(ctx, arn)
			out = append(out, map[string]any{
				"arn":                arn,
				"type":               "application_load_balancer",
				"scheme":             string(lb.Scheme),
				"public_facing":      lb.Scheme == elbv2types.LoadBalancerSchemeEnumInternetFacing,
				"web_acl_associated": associated,
				"web_acl_arn":        aclArn,
			})
		}
	}
	return out, nil
}

// webACLForResource returns the ARN of the WebACL associated with a regional
// resource, or ("", false) when none is associated. A lookup error is treated
// as "no association" so the downstream control fails closed rather than
// assuming coverage.
func (c *Collector) webACLForResource(ctx context.Context, arn string) (string, bool) {
	res, err := c.wafv2.GetWebACLForResource(ctx, &wafv2.GetWebACLForResourceInput{ResourceArn: aws.String(arn)})
	if err != nil || res.WebACL == nil {
		return "", false
	}
	return aws.ToString(res.WebACL.ARN), true
}

// wafCloudFront lists CloudFront distributions. A distribution carries its
// associated WebACL directly on the summary (WebACLId), so no separate WAF
// call is needed. CloudFront distributions are inherently internet-facing;
// public_facing tracks whether the distribution is enabled.
func (c *Collector) wafCloudFront(ctx context.Context) ([]map[string]any, error) {
	out := make([]map[string]any, 0)
	pager := cloudfront.NewListDistributionsPaginator(c.cloudfront, &cloudfront.ListDistributionsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("listing CloudFront distributions", err)
		}
		if page.DistributionList == nil {
			continue
		}
		for _, d := range page.DistributionList.Items {
			webACL := aws.ToString(d.WebACLId)
			out = append(out, map[string]any{
				"arn":                aws.ToString(d.ARN),
				"type":               "cloudfront_distribution",
				"scheme":             "internet-facing",
				"public_facing":      aws.ToBool(d.Enabled),
				"web_acl_associated": webACL != "",
				"web_acl_arn":        webACL,
			})
		}
	}
	return out, nil
}
