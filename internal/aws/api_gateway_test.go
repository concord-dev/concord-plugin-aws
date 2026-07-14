package aws_test

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigwtypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"

	"github.com/concord-dev/concord-plugin-aws/internal/aws"
)

type fakeAPIGateway struct {
	apis       []apigwtypes.RestApi
	resources  map[string][]apigwtypes.Resource
	stages     map[string][]apigwtypes.Stage
	usagePlans []apigwtypes.UsagePlan
}

func (f fakeAPIGateway) GetRestApis(context.Context, *apigateway.GetRestApisInput, ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
	return &apigateway.GetRestApisOutput{Items: f.apis}, nil
}

func (f fakeAPIGateway) GetResources(_ context.Context, in *apigateway.GetResourcesInput, _ ...func(*apigateway.Options)) (*apigateway.GetResourcesOutput, error) {
	return &apigateway.GetResourcesOutput{Items: f.resources[awssdk.ToString(in.RestApiId)]}, nil
}

func (f fakeAPIGateway) GetStages(_ context.Context, in *apigateway.GetStagesInput, _ ...func(*apigateway.Options)) (*apigateway.GetStagesOutput, error) {
	return &apigateway.GetStagesOutput{Item: f.stages[awssdk.ToString(in.RestApiId)]}, nil
}

func (f fakeAPIGateway) GetUsagePlans(context.Context, *apigateway.GetUsagePlansInput, ...func(*apigateway.Options)) (*apigateway.GetUsagePlansOutput, error) {
	return &apigateway.GetUsagePlansOutput{Items: f.usagePlans}, nil
}

func TestCollectAPIGateway(t *testing.T) {
	c := &aws.Collector{}
	aws.WithAPIGateway(fakeAPIGateway{
		apis: []apigwtypes.RestApi{
			{Id: awssdk.String("api-1"), Name: awssdk.String("public-api")},
			{Id: awssdk.String("api-2"), Name: awssdk.String("private-api"),
				EndpointConfiguration: &apigwtypes.EndpointConfiguration{Types: []apigwtypes.EndpointType{apigwtypes.EndpointTypePrivate}}},
		},
		resources: map[string][]apigwtypes.Resource{
			// public-api validates its mutating method.
			"api-1": {{ResourceMethods: map[string]apigwtypes.Method{
				"GET":  {HttpMethod: awssdk.String("GET")},
				"POST": {HttpMethod: awssdk.String("POST"), RequestValidatorId: awssdk.String("rv-1")},
			}}},
			// private-api has a POST with no validator.
			"api-2": {{ResourceMethods: map[string]apigwtypes.Method{
				"POST": {HttpMethod: awssdk.String("POST")},
			}}},
		},
		stages: map[string][]apigwtypes.Stage{
			"api-1": {{StageName: awssdk.String("prod")}},
		},
		usagePlans: []apigwtypes.UsagePlan{
			{ApiStages: []apigwtypes.ApiStage{{ApiId: awssdk.String("api-1"), Stage: awssdk.String("prod")}}},
		},
	})(c)
	// Collector region is "" in tests, so the stage ARN carries an empty region.
	aws.WithWAFv2(fakeWAFv2{
		associated: map[string]string{"arn:aws:apigateway:::/restapis/api-1/stages/prod": "acl-arn"},
		rules:      map[string]int{"arn:aws:apigateway:::/restapis/api-1/stages/prod": 5},
	})(c)

	out, err := c.Collect(context.Background(), plugin.EvidenceRef{Type: "api_gateway"})
	require.NoError(t, err)
	m := out.(map[string]any)

	apis := m["apis"].([]map[string]any)
	require.Len(t, apis, 2)
	byName := map[string]map[string]any{}
	for _, a := range apis {
		byName[a["name"].(string)] = a
	}

	pub := byName["public-api"]
	assert.Equal(t, true, pub["public"])
	assert.Equal(t, true, pub["request_validation_enabled"], "validated POST + read-only GET counts as validated")
	assert.Equal(t, true, pub["waf_attached"])
	assert.Equal(t, 5, pub["waf_rule_count"])
	assert.Equal(t, true, pub["usage_plan_attached"])

	priv := byName["private-api"]
	assert.Equal(t, false, priv["public"])
	assert.Equal(t, false, priv["request_validation_enabled"], "POST with no validator fails validation")
	assert.Equal(t, false, priv["waf_attached"])
	assert.Equal(t, 0, priv["waf_rule_count"])
	assert.Equal(t, false, priv["usage_plan_attached"])
}
