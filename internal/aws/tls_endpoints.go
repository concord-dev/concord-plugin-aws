package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectTLSEndpoints reports the account's TLS-terminating endpoints: S3
// buckets (with their resource policy, to check SecureTransport enforcement)
// and ELBv2 load balancers with their listeners. Shape:
//
//	{ fetched_at,
//	  buckets: [ { name, tags, policy } ],
//	  load_balancers: [ { name, tags, listeners: [ { port, protocol, ssl_policy } ] } ] }
//
// This backs the aws_tls_endpoints evidence type the HIPAA §164.312(e),
// FedRAMP, and NIST-CSF in-transit-encryption controls read.
func (c *Collector) collectTLSEndpoints(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	buckets, err := c.s3BucketPolicies(ctx)
	if err != nil {
		return nil, err
	}
	lbs, err := c.loadBalancers(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"fetched_at":     time.Now().UTC().Format(time.RFC3339),
		"buckets":        buckets,
		"load_balancers": lbs,
	}, nil
}

func (c *Collector) loadBalancers(ctx context.Context) ([]map[string]any, error) {
	out := make([]map[string]any, 0)
	pager := elbv2.NewDescribeLoadBalancersPaginator(c.elbv2, &elbv2.DescribeLoadBalancersInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("describing load balancers", err)
		}
		for _, lb := range page.LoadBalancers {
			arn := aws.ToString(lb.LoadBalancerArn)
			listeners, err := c.lbListeners(ctx, arn)
			if err != nil {
				return nil, err
			}
			out = append(out, map[string]any{
				"name":      aws.ToString(lb.LoadBalancerName),
				"tags":      c.lbTags(ctx, arn),
				"listeners": listeners,
			})
		}
	}
	return out, nil
}

func (c *Collector) lbListeners(ctx context.Context, lbArn string) ([]map[string]any, error) {
	listeners := make([]map[string]any, 0)
	pager := elbv2.NewDescribeListenersPaginator(c.elbv2, &elbv2.DescribeListenersInput{LoadBalancerArn: aws.String(lbArn)})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("describing listeners for "+lbArn, err)
		}
		for _, l := range page.Listeners {
			listeners = append(listeners, map[string]any{
				"port":       aws.ToInt32(l.Port),
				"protocol":   string(l.Protocol),
				"ssl_policy": aws.ToString(l.SslPolicy),
			})
		}
	}
	return listeners, nil
}

func (c *Collector) lbTags(ctx context.Context, arn string) map[string]any {
	tags := map[string]any{}
	out, err := c.elbv2.DescribeTags(ctx, &elbv2.DescribeTagsInput{ResourceArns: []string{arn}})
	if err != nil || out == nil {
		return tags
	}
	for _, td := range out.TagDescriptions {
		for _, t := range td.Tags {
			tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
	}
	return tags
}
