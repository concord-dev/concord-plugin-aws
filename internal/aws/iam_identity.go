package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

const adminAccessPolicyARN = "arn:aws:iam::aws:policy/AdministratorAccess"

// collectIAMIdentityInventory reports the account's IAM user inventory plus
// root-usage and account-key facts from the credential report. Shape:
//
//	{ fetched_at, account_access_keys_present, root_last_used_days_ago,
//	  shared_credentials, users: [ { username, is_service_account,
//	  has_console_login } ] }
//
// This backs the iam_identity_inventory evidence type the HIPAA
// unique-user-identification and ISO 27001 A.5.16 controls read. A user with no
// console login is treated as a service account. shared_credentials is emitted
// empty — the account cannot reliably detect credential sharing.
func (c *Collector) collectIAMIdentityInventory(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	report, _, err := c.credentialReportUsers(ctx)
	if err != nil {
		return nil, err
	}
	summary, err := c.iam.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, wrapErr("iam account summary", err)
	}
	accessKeys := 0
	if summary != nil {
		accessKeys = int(summary.SummaryMap["AccountAccessKeysPresent"])
	}

	rootDays := -1
	users := make([]map[string]any, 0, len(report))
	for _, row := range report {
		name, _ := row["user"].(string)
		if name == "<root_account>" {
			rootDays = lastUsedDaysAgo(row)
			continue
		}
		console, _ := row["password_enabled"].(bool)
		users = append(users, map[string]any{
			"username":           name,
			"has_console_login":  console,
			"is_service_account": !console,
		})
	}
	return map[string]any{
		"fetched_at":                  time.Now().UTC().Format(time.RFC3339),
		"account_access_keys_present": accessKeys,
		"root_last_used_days_ago":     rootDays,
		"shared_credentials":          []any{},
		"users":                       users,
	}, nil
}

// collectIAMPrivilegedPrincipals reports IAM users with administrator-level
// access, with their MFA and access-key facts. Shape:
//
//	{ fetched_at, administrators: [ { username, has_access_key, mfa_enabled } ] }
//
// This backs the iam_privileged_principals evidence type the ISO 27001 A.8.2,
// NIST-CSF, and PCI-DSS 7 privileged-access controls read. A user is an
// administrator when it has the AWS-managed AdministratorAccess policy or any
// attached policy that allows Action "*" on Resource "*".
func (c *Collector) collectIAMPrivilegedPrincipals(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	report, _, err := c.credentialReportUsers(ctx)
	if err != nil {
		return nil, err
	}
	credByUser := make(map[string]map[string]any, len(report))
	for _, row := range report {
		if name, ok := row["user"].(string); ok {
			credByUser[name] = row
		}
	}

	docCache := map[string]map[string]any{}
	admins := make([]map[string]any, 0)
	pager := iam.NewListUsersPaginator(c.iam, &iam.ListUsersInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("listing IAM users", err)
		}
		for _, u := range page.Users {
			name := aws.ToString(u.UserName)
			isAdmin, err := c.userHasAdmin(ctx, name, docCache)
			if err != nil {
				return nil, err
			}
			if !isAdmin {
				continue
			}
			cred := credByUser[name]
			admins = append(admins, map[string]any{
				"username":       name,
				"has_access_key": hasActiveAccessKey(cred),
				"mfa_enabled":    boolField(cred, "mfa_active"),
			})
		}
	}
	return map[string]any{
		"fetched_at":     time.Now().UTC().Format(time.RFC3339),
		"administrators": admins,
	}, nil
}

func (c *Collector) userHasAdmin(ctx context.Context, user string, cache map[string]map[string]any) (bool, error) {
	out, err := c.iam.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: aws.String(user)})
	if err != nil {
		return false, wrapErr("listing attached policies for user "+user, err)
	}
	for _, p := range out.AttachedPolicies {
		arn := aws.ToString(p.PolicyArn)
		if arn == adminAccessPolicyARN {
			return true, nil
		}
		doc, err := c.policyDocument(ctx, arn, cache)
		if err != nil {
			return false, err
		}
		if documentGrantsFullAdmin(doc) {
			return true, nil
		}
	}
	return false, nil
}

// documentGrantsFullAdmin reports whether a decoded policy document allows
// Action "*" on Resource "*" in any Allow statement.
func documentGrantsFullAdmin(doc map[string]any) bool {
	for _, stmt := range statements(doc) {
		if effect, _ := stmt["Effect"].(string); effect != "Allow" {
			continue
		}
		if valuesContain(stmt["Action"], "*") && valuesContain(stmt["Resource"], "*") {
			return true
		}
	}
	return false
}

// statements normalises a policy document's Statement (object or array) to a
// slice of statement objects.
func statements(doc map[string]any) []map[string]any {
	switch s := doc["Statement"].(type) {
	case []any:
		out := make([]map[string]any, 0, len(s))
		for _, e := range s {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	case map[string]any:
		return []map[string]any{s}
	}
	return nil
}

// valuesContain reports whether an IAM field (string or []string) contains want.
func valuesContain(v any, want string) bool {
	switch t := v.(type) {
	case string:
		return t == want
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func lastUsedDaysAgo(row map[string]any) int {
	best := -1
	consider := func(v any) {
		if d, ok := v.(int); ok && d >= 0 && (best < 0 || d < best) {
			best = d
		}
	}
	consider(row["password_last_used_days_ago"])
	if keys, ok := row["access_keys"].([]map[string]any); ok {
		for _, k := range keys {
			consider(k["last_used_days_ago"])
		}
	}
	return best
}

func hasActiveAccessKey(row map[string]any) bool {
	keys, ok := row["access_keys"].([]map[string]any)
	if !ok {
		return false
	}
	for _, k := range keys {
		if active, _ := k["active"].(bool); active {
			return true
		}
	}
	return false
}

func boolField(row map[string]any, key string) bool {
	if row == nil {
		return false
	}
	b, _ := row[key].(bool)
	return b
}
