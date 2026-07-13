# concord-plugin-aws

Concord plugin for AWS — reads IAM, S3, and CloudTrail evidence using
the AWS SDK v2's standard credentials chain.

## Evidence types

| Type | Returns |
|---|---|
| `s3_bucket_encryption` | per-bucket SSE config + algorithm |
| `s3_public_access_block` | account-level + per-bucket public-access settings |
| `iam_account_summary` | output of `aws iam get-account-summary` |
| `iam_password_policy` | output of `aws iam get-account-password-policy` |
| `iam_credential_report` | parsed `iam:GenerateCredentialReport` CSV |
| `cloudtrail_trails` | every trail, region, log file integrity flag |
| `storage_encryption` | encryption-at-rest for S3 buckets, RDS instances, and EBS volumes, with each resource's tags |
| `security_groups` | EC2 security groups with inbound/outbound rules per CIDR + scope tag |
| `iam_roles` | IAM roles with session ceiling, tags, and decoded trust policy |
| `iam_policies` | IAM identities with attached managed policies + decoded documents |
| `s3_bucket_policy` | per-bucket resource policy (decoded) + tags |
| `vpc_flow_logs` | per-VPC active flow-log status |
| `config_recorder_status` | AWS Config recorder coverage (recording + all-supported) |
| `guardduty_status` | GuardDuty detector status per region |
| `ssm_patch_compliance` | SSM per-instance patch compliance |

## Required IAM permissions

See [examples/iam-readonly-policy.json](https://github.com/concord-dev/concord/blob/main/examples/iam-readonly-policy.json).

## Optional env

- `AWS_REGION` — defaults to `us-east-1`
- Anything the AWS SDK v2 credentials chain recognises (`AWS_PROFILE`,
  `AWS_ACCESS_KEY_ID`, IMDS, etc.)

## Install

```sh
make install
```
