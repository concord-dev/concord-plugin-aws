package aws

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectIAMPolicies reports every IAM identity (user, role, group) with its
// attached managed policies and each policy's decoded document. Shape:
//
//	{ fetched_at, identities: [ { name, type, attached_policies: [
//	    { policy_name, arn, is_aws_managed, document } ] } ] }
//
// This backs the iam_policies evidence type the FedRAMP AC-3/AC-6, HIPAA
// access-control, and PCI-DSS Req-7 least-privilege controls read (they inspect
// document.Statement for wildcard grants). Policy documents are fetched once per
// ARN and cached, since a managed policy is commonly attached to many
// identities.
func (c *Collector) collectIAMPolicies(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cache := map[string]map[string]any{}
	identities := make([]map[string]any, 0)

	userPager := iam.NewListUsersPaginator(c.iam, &iam.ListUsersInput{})
	for userPager.HasMorePages() {
		page, err := userPager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("listing IAM users", err)
		}
		for _, u := range page.Users {
			name := aws.ToString(u.UserName)
			out, err := c.iam.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: aws.String(name)})
			if err != nil {
				return nil, wrapErr("listing attached policies for user "+name, err)
			}
			entries, err := c.policyEntries(ctx, out.AttachedPolicies, cache)
			if err != nil {
				return nil, err
			}
			identities = append(identities, identity(name, "user", entries))
		}
	}

	rolePager := iam.NewListRolesPaginator(c.iam, &iam.ListRolesInput{})
	for rolePager.HasMorePages() {
		page, err := rolePager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("listing IAM roles", err)
		}
		for _, r := range page.Roles {
			name := aws.ToString(r.RoleName)
			out, err := c.iam.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(name)})
			if err != nil {
				return nil, wrapErr("listing attached policies for role "+name, err)
			}
			entries, err := c.policyEntries(ctx, out.AttachedPolicies, cache)
			if err != nil {
				return nil, err
			}
			identities = append(identities, identity(name, "role", entries))
		}
	}

	groupPager := iam.NewListGroupsPaginator(c.iam, &iam.ListGroupsInput{})
	for groupPager.HasMorePages() {
		page, err := groupPager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("listing IAM groups", err)
		}
		for _, g := range page.Groups {
			name := aws.ToString(g.GroupName)
			out, err := c.iam.ListAttachedGroupPolicies(ctx, &iam.ListAttachedGroupPoliciesInput{GroupName: aws.String(name)})
			if err != nil {
				return nil, wrapErr("listing attached policies for group "+name, err)
			}
			entries, err := c.policyEntries(ctx, out.AttachedPolicies, cache)
			if err != nil {
				return nil, err
			}
			identities = append(identities, identity(name, "group", entries))
		}
	}

	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"identities": identities,
	}, nil
}

func identity(name, typ string, attached []map[string]any) map[string]any {
	return map[string]any{"name": name, "type": typ, "attached_policies": attached}
}

func (c *Collector) policyEntries(ctx context.Context, attached []iamtypes.AttachedPolicy, cache map[string]map[string]any) ([]map[string]any, error) {
	entries := make([]map[string]any, 0, len(attached))
	for _, p := range attached {
		arn := aws.ToString(p.PolicyArn)
		doc, err := c.policyDocument(ctx, arn, cache)
		if err != nil {
			return nil, err
		}
		entries = append(entries, map[string]any{
			"policy_name":    aws.ToString(p.PolicyName),
			"arn":            arn,
			"is_aws_managed": strings.HasPrefix(arn, "arn:aws:iam::aws:"),
			"document":       doc,
		})
	}
	return entries, nil
}

// policyDocument fetches and decodes a managed policy's active version document,
// caching by ARN so a widely-attached policy is fetched once.
func (c *Collector) policyDocument(ctx context.Context, arn string, cache map[string]map[string]any) (map[string]any, error) {
	if doc, ok := cache[arn]; ok {
		return doc, nil
	}
	pol, err := c.iam.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(arn)})
	if err != nil {
		return nil, wrapErr("getting policy "+arn, err)
	}
	version := ""
	if pol.Policy != nil {
		version = aws.ToString(pol.Policy.DefaultVersionId)
	}
	ver, err := c.iam.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: aws.String(arn), VersionId: aws.String(version)})
	if err != nil {
		return nil, wrapErr("getting policy version for "+arn, err)
	}
	doc := map[string]any{}
	if ver.PolicyVersion != nil {
		doc = decodePolicyDocument(ver.PolicyVersion.Document)
	}
	cache[arn] = doc
	return doc, nil
}
