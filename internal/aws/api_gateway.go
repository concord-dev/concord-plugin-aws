package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigwtypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// mutatingMethods are the HTTP methods that accept a request body and so are
// the ones request validation is meaningful for.
var mutatingMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true}

// collectAPIGateway reports each REST API's exposure and the request-integrity
// controls in front of it. Shape:
//
//	{ fetched_at,
//	  apis: [ { name, public, request_validation_enabled,
//	            waf_attached, waf_rule_count, usage_plan_attached } ] }
//
// This backs the api_gateway evidence type the SOC 2 PI1.1 input-validation
// control reads (public APIs must validate input and cap request rate).
//
//   - public: the API's endpoint type is not PRIVATE (EDGE/REGIONAL are
//     internet-reachable; a nil endpoint config defaults to the public EDGE type).
//   - request_validation_enabled: every mutating method (POST/PUT/PATCH) on the
//     API has a request validator attached. An API with no mutating methods has
//     nothing to validate and reports true.
//   - waf_attached / waf_rule_count: any stage of the API has a WAFv2 WebACL
//     associated, and the rule count of the largest such WebACL.
//   - usage_plan_attached: some usage plan references a stage of the API.
func (c *Collector) collectAPIGateway(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	plannedAPIs, err := c.usagePlanAPIs(ctx)
	if err != nil {
		return nil, err
	}

	apis := make([]map[string]any, 0)
	pager := apigateway.NewGetRestApisPaginator(c.apigateway, &apigateway.GetRestApisInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("listing API Gateway REST APIs", err)
		}
		for _, api := range page.Items {
			id := aws.ToString(api.Id)
			rv, err := c.apiRequestValidation(ctx, id)
			if err != nil {
				return nil, err
			}
			wafAttached, ruleCount, err := c.apiWAF(ctx, id)
			if err != nil {
				return nil, err
			}
			apis = append(apis, map[string]any{
				"name":                       aws.ToString(api.Name),
				"public":                     isPublicEndpoint(api.EndpointConfiguration),
				"request_validation_enabled": rv,
				"waf_attached":               wafAttached,
				"waf_rule_count":             ruleCount,
				"usage_plan_attached":        plannedAPIs[id],
			})
		}
	}
	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"apis":       apis,
	}, nil
}

// isPublicEndpoint reports whether a REST API is internet-reachable. A REST API
// is private only when its endpoint configuration explicitly lists PRIVATE; a
// nil configuration defaults to the public EDGE endpoint type.
func isPublicEndpoint(cfg *apigwtypes.EndpointConfiguration) bool {
	if cfg == nil {
		return true
	}
	for _, t := range cfg.Types {
		if t == apigwtypes.EndpointTypePrivate {
			return false
		}
	}
	return true
}

// apiRequestValidation reports whether every mutating method on the API has a
// request validator attached. GetResources with the "methods" embed returns
// each method's requestValidatorId in a single paginated call per API.
func (c *Collector) apiRequestValidation(ctx context.Context, apiID string) (bool, error) {
	pager := apigateway.NewGetResourcesPaginator(c.apigateway, &apigateway.GetResourcesInput{
		RestApiId: aws.String(apiID),
		Embed:     []string{"methods"},
	})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return false, wrapErr(fmt.Sprintf("getting resources for API %q", apiID), err)
		}
		for _, r := range page.Items {
			for method, m := range r.ResourceMethods {
				if !mutatingMethods[method] {
					continue
				}
				if aws.ToString(m.RequestValidatorId) == "" {
					return false, nil
				}
			}
		}
	}
	return true, nil
}

// apiWAF reports whether any stage of the API has a WAFv2 WebACL associated and
// the rule count of the largest such WebACL. WAF associates with a stage, so
// each stage's regional ARN is checked.
func (c *Collector) apiWAF(ctx context.Context, apiID string) (bool, int, error) {
	stages, err := c.apigateway.GetStages(ctx, &apigateway.GetStagesInput{RestApiId: aws.String(apiID)})
	if err != nil {
		return false, 0, wrapErr(fmt.Sprintf("getting stages for API %q", apiID), err)
	}
	attached := false
	maxRules := 0
	for _, s := range stages.Item {
		arn := fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s/stages/%s", c.region, apiID, aws.ToString(s.StageName))
		res, err := c.wafv2.GetWebACLForResource(ctx, &wafv2.GetWebACLForResourceInput{ResourceArn: aws.String(arn)})
		if err != nil || res.WebACL == nil {
			continue
		}
		attached = true
		if n := len(res.WebACL.Rules); n > maxRules {
			maxRules = n
		}
	}
	return attached, maxRules, nil
}

// usagePlanAPIs returns the set of REST API ids referenced by any usage plan.
func (c *Collector) usagePlanAPIs(ctx context.Context) (map[string]bool, error) {
	out := map[string]bool{}
	pager := apigateway.NewGetUsagePlansPaginator(c.apigateway, &apigateway.GetUsagePlansInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("listing API Gateway usage plans", err)
		}
		for _, p := range page.Items {
			for _, s := range p.ApiStages {
				out[aws.ToString(s.ApiId)] = true
			}
		}
	}
	return out, nil
}
