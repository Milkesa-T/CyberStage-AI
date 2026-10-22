# PB-004: Cloud IAM Credential Exposure and Privilege Escalation Playbook

## 1. Overview and Threat Profile
- **Playbook ID**: PB-004-CLOUD-IAM-LEAK
- **Category**: UNAUTHORIZED_ACCESS / PRIVILEGE_ESCALATION
- **Description**: Response standard for leaked cloud API access keys (AWS, GCP, Azure), abnormal IAM role assumptions, privilege escalation attempts, and unexpected infrastructure modifications.

## 2. Key Indicators of Compromise (IOCs)
- API calls originating from anomalous geographic locations, Tor exit nodes, or VPN provider IP ranges.
- High-volume enumeration API calls (`Describe*`, `List*`, `GetCallerIdentity`, `GetAccountAuthorizationDetails`).
- Unauthorized creation of new IAM users, access keys, or inline administrator policies (`AttachUserPolicy`, `CreateAccessKey`).
- Public repository alert from GitGuardian or GitHub Secret Scanning indicating committed cloud credentials.

## 3. Severity Matrix
- **LOW**: Inactive or expired access key published publicly; no API calls observed in audit logs.
- **MEDIUM**: Active access key used from unusual IP, but limited to read-only reconnaissance permissions; blocked by policy.
- **HIGH**: Active access key executed administrative calls, created resources, or bypassed MFA policies.
- **CRITICAL**: Creation of backdoor IAM credentials, modification of cloud trail logging configurations (`StopLogging`), or evidence of data exfiltration from storage buckets (S3 / GCS).

## 4. Triage and Initial Verification Steps
1. **Identify Compromised Identity & Key ID**:
   Extract `accessKeyId`, `arn`, and `userIdentity` from CloudTrail / Cloud Audit Logs.
2. **Review Chronological API History**:
   Query CloudTrail events associated with the key for the past 7 days to reconstruct attacker actions and scope.
3. **Assess Geo & IP Anomalies**:
   Cross-reference user agent strings and originating IP addresses against standard company VPN and office egress ranges.

## 5. Containment Actions
1. **Deactivate Exposed Access Key**:
   Immediately set the exposed access key status to `Inactive` or delete it via Cloud CLI:
   `aws iam update-access-key --access-key-id <KEY_ID> --status Inactive --user-name <USER>`
2. **Attach Deny-All Inline Policy**:
   Attach an explicit `DenyAll` boundary policy to the compromised IAM user/role to instantly invalidate cached STS sessions.
3. **Revoke Active IAM Sessions**:
   Issue session revocation to terminate all active assumed-role STS tokens.

## 6. Eradication and Remediation
- Delete any backdoor IAM users, keys, or security group rules created by the threat actor.
- Rotate all secrets and credentials accessible by the compromised identity.
- Enforce IAM guardrails, automated secret scanning in CI/CD, and mandatory MFA on sensitive CLI roles.
