package aws

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectIAMRoles reports every IAM role with its session ceiling, tags, and
// decoded trust policy. Shape:
//
//	{ fetched_at, roles: [ { role_name, arn, tags,
//	    max_session_duration_seconds, assume_role_policy } ] }
//
// This backs the iam_roles evidence type the FedRAMP session controls
// (AC-11/AC-12) and HIPAA automatic-logoff / emergency-access controls read.
// assume_role_policy is the trust document decoded from its IAM URL-encoding.
func (c *Collector) collectIAMRoles(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	roles := make([]map[string]any, 0)
	paginator := iam.NewListRolesPaginator(c.iam, &iam.ListRolesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("listing IAM roles", err)
		}
		for _, r := range page.Roles {
			name := aws.ToString(r.RoleName)
			role := map[string]any{
				"role_name":                    name,
				"arn":                          aws.ToString(r.Arn),
				"max_session_duration_seconds": aws.ToInt32(r.MaxSessionDuration),
				"assume_role_policy":           decodePolicyDocument(r.AssumeRolePolicyDocument),
			}
			tags, err := c.roleTags(ctx, name)
			if err != nil {
				return nil, err
			}
			role["tags"] = tags
			roles = append(roles, role)
		}
	}
	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"roles":      roles,
	}, nil
}

func (c *Collector) roleTags(ctx context.Context, roleName string) (map[string]any, error) {
	out, err := c.iam.ListRoleTags(ctx, &iam.ListRoleTagsInput{RoleName: aws.String(roleName)})
	if err != nil {
		return nil, wrapErr("listing tags for role "+roleName, err)
	}
	return iamTags(out.Tags), nil
}

func iamTags(tags []iamtypes.Tag) map[string]any {
	m := map[string]any{}
	for _, t := range tags {
		m[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}
	return m
}

// decodePolicyDocument turns an IAM policy document — a URL-encoded JSON string
// as returned by the IAM API — into a structured object. A missing or
// undecodable document yields an empty object so controls fail closed rather
// than panicking on a nil.
func decodePolicyDocument(doc *string) map[string]any {
	out := map[string]any{}
	raw := aws.ToString(doc)
	if raw == "" {
		return out
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		decoded = raw
	}
	_ = json.Unmarshal([]byte(decoded), &out)
	return out
}
