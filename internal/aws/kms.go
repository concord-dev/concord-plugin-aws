package aws

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	plugin "github.com/concord-dev/concord-plugin-sdk/plugin"
)

// collectKMSKeys reports customer KMS keys with rotation state and tags. Shape:
//
//	{ fetched_at, keys: [ { key_id, tags, key_state, rotation_enabled,
//	    rotation_period_days } ] }
//
// This backs the kms_keys evidence type the PCI-DSS key-management controls
// read (they require rotation enabled at least annually on cardholder-data
// keys). AWS-managed keys (KeyManager=AWS) are skipped — their rotation is not
// customer-controllable.
func (c *Collector) collectKMSKeys(_ plugin.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	keys := make([]map[string]any, 0)
	pager := kms.NewListKeysPaginator(c.kms, &kms.ListKeysInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, wrapErr("listing KMS keys", err)
		}
		for _, k := range page.Keys {
			id := aws.ToString(k.KeyId)
			desc, err := c.kms.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: k.KeyId})
			if err != nil {
				return nil, wrapErr("describing KMS key "+id, err)
			}
			md := desc.KeyMetadata
			if md == nil || md.KeyManager != "CUSTOMER" {
				continue // only customer-managed keys have controllable rotation
			}
			rot, err := c.kms.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: k.KeyId})
			if err != nil {
				return nil, wrapErr("getting rotation status for KMS key "+id, err)
			}
			keys = append(keys, map[string]any{
				"key_id":               aws.ToString(md.Arn),
				"tags":                 c.kmsTags(ctx, id),
				"key_state":            string(md.KeyState),
				"rotation_enabled":     rot.KeyRotationEnabled,
				"rotation_period_days": aws.ToInt32(rot.RotationPeriodInDays),
			})
		}
	}
	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"keys":       keys,
	}, nil
}

func (c *Collector) kmsTags(ctx context.Context, keyID string) map[string]any {
	tags := map[string]any{}
	out, err := c.kms.ListResourceTags(ctx, &kms.ListResourceTagsInput{KeyId: aws.String(keyID)})
	if err != nil {
		return tags // tags are best-effort; a rotation finding must not depend on them
	}
	for _, t := range out.Tags {
		tags[aws.ToString(t.TagKey)] = aws.ToString(t.TagValue)
	}
	return tags
}
