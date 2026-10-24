# PB-006: Cloud Infrastructure and IAM Identity Compromise Response Playbook

## 1. Overview and Threat Profile
- **Playbook ID**: PB-006-CLOUD-IAM
- **Category**: CLOUD_INFRASTRUCTURE / UNAUTHORIZED_ACCESS / PRIVILEGE_ESCALATION
- **Framework Alignment**: AWS Security Incident Response Guide, CIS AWS/Azure/GCP Benchmarks, MITRE ATT&CK T1078.004 (Cloud Accounts), T1552.005 (Cloud Instance Metadata API), T1098.001 (Additional Cloud Credentials)
- **Description**: Standard operating procedures for triaging, containing, and remediating unauthorized administrative activity, long-term API access key compromise, EC2/VM metadata service abuse, and cloud tenant privilege escalation.

## 2. Key Indicators of Compromise (IOCs)
- Long-term IAM access key (`AKIA...` or Azure Service Principal) executing administrative API calls from unknown external WAN IPs or anomalous geographic locations.
- Invasive privilege escalation actions in CloudTrail / Azure Activity Log: `CreateAccessKey`, `AttachUserPolicy`, `PutRolePolicy`, `AuthorizeSecurityGroupIngress` with CIDR `0.0.0.0/0`.
- Attempts to query the AWS Instance Metadata Service (IMDSv1 at `169.254.169.254`) from application containers or web applications via Server-Side Request Forgery (SSRF).
- Mass creation of compute instances (EC2 GPU instances, Google Compute Engine) for illicit cryptomining or staging attacks.
- Tampering with logging infrastructure: `StopLogging`, `DeleteTrail`, or disabling AWS GuardDuty / Microsoft Defender for Cloud.

## 3. Severity Matrix
- **LOW**: CloudTrail anomaly alert for an unrecognized user-agent using valid MFA from an authorized corporate IP.
- **MEDIUM**: Read-only reconnaissance API calls (`DescribeInstances`, `ListBuckets`, `GetAccountSummary`) from an unusual foreign IP using a developer access key.
- **HIGH**: Write-level API calls creating new IAM access keys, modifying security groups, or downloading customer data buckets from an untrusted external IP.
- **CRITICAL**: Root account usage without approved change window; security group opened to `0.0.0.0/0` across all ports; modification of CloudTrail trails; simultaneous exfiltration from production S3/Blob storage.

## 4. Triage and Initial Verification Steps
1. **Identify the Compromised Identity**:
   Determine whether the event involves a root user, federated SSO identity, IAM user, or EC2/Lambda role credential (`ASIA...`).
2. **Review CloudTrail / Activity Log Trail**:
   Extract all events executed by the target access key ID for the past 72 hours using AWS CLI:
   `aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<ACCESS_KEY_ID>`
3. **Inspect Blast Radius Across Cloud Regions**:
   Attacker scripts frequently deploy infrastructure across secondary regions (e.g., `us-east-2`, `ap-southeast-1`) not actively monitored by primary teams.
4. **Verify S3 / Cloud Storage Access Logs**:
   Query CloudWatch or Athena for S3 server access logs to identify any unauthorized `GetObject` calls originating from the suspicious session.

## 5. Containment Actions
1. **Deactivate Compromised Access Key**:
   Execute immediate revocation of active long-term credentials via AWS CLI or IAM console:
   `aws iam update-access-key --access-key-id <ACCESS_KEY_ID> --status Inactive`
2. **Attach Deny-All Boundary Policy**:
   Attach an explicit deny policy directly to the compromised IAM user or role to supersede all existing permissions:
   `aws iam attach-user-policy --user-name <USER> --policy-arn arn:aws:iam::aws:policy/AWSDenyAll`
3. **Invalidate Active Session Tokens**:
   Revoke temporary STS session tokens by applying an inline policy with an `aws:CurrentTime` condition or deleting active session profiles.
4. **Revert Security Group Ingress Exposures**:
   Immediately revoke open ingress rules (e.g., `0.0.0.0/0` on management ports 22, 3389, 5432) using `aws ec2 revoke-security-group-ingress`.

## 6. Eradication and Hardening
- Enforce mandatory IMDSv2 (`HttpTokens=required`) across all EC2 launch templates and instances to prevent SSRF credential theft.
- Migrate from static, long-term IAM access keys (`AKIA`) to short-lived temporary roles via AWS IAM Identity Center or OIDC federation.
- Configure SCPs (Service Control Policies) at the AWS Organizations level prohibiting disabling of CloudTrail and GuardDuty.
- Rotate all secrets stored in AWS Secrets Manager or Parameter Store that may have been accessed by the compromised principal.
