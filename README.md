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
| `kms_keys` | customer KMS keys: rotation state + tags |
| `network_acls` | network ACL rule entries |
| `s3_bucket_integrity` | per-bucket versioning + Object Lock |
| `ec2_inventory` | EC2 instances + Config-recording flag |
| `cloudtrail_event_selectors` | per-trail event selectors |
| `iam_privileged_principals` | IAM admins with MFA + access-key facts |
| `iam_identity_inventory` | IAM user inventory + root/account-key facts |
| `config_conformance_status` | AWS Config conformance-pack compliance |
| `s3_lifecycle` | per-bucket lifecycle rules + Object Lock |
| `anti_malware_status` | GuardDuty + Inspector threat-detection posture |
| `integrity_monitoring` | CloudTrail log-file validation + Config recording |
| `cloudwatch_alarms` | metric filters + the alarms watching them |
| `cloudwatch_log_groups` | log-group retention, KMS, classification tags |
| `aws_tls_endpoints` | S3 bucket policies + ELB listeners (TLS enforcement) |
| `inspector_findings` | Inspector enablement + critical/high finding counts |

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
