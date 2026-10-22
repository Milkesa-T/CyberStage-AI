# PB-002: Phishing and Malicious Email Triage Playbook

## 1. Overview and Threat Profile
- **Playbook ID**: PB-002-PHISHING
- **Category**: PHISHING / SOCIAL_ENGINEERING
- **Description**: Standard operating procedure for triaging reported suspicious emails, credential harvesting landing pages, malicious QR codes (quishing), and weaponized attachments (PDF, HTML, ZIP, ISO).

## 2. Key Indicators of Compromise (IOCs)
- Mismatches in email authentication: `spf=fail`, `dkim=fail`, or `dmarc=fail` in email headers.
- Display name spoofing (e.g., impersonating the CEO, IT Helpdesk, or HR payroll department) with external sender domains.
- Lookalike or punycode domain names (e.g., `micros0ft-login.com`, `payro11-update.org`).
- Embedded hyperlink redirects to newly registered domains (< 30 days old) or credential capture portals.
- Suspicious attachments containing macro-enabled Office files, disguised executable extensions, or obfuscated JavaScript.

## 3. Severity Matrix
- **LOW**: Phishing email delivered to spam/quarantine; no users interacted with links or attachments.
- **MEDIUM**: Phishing email delivered to multiple inboxes; no confirmed link clicks or credential submissions.
- **HIGH**: One or more recipients clicked the embedded link or opened the attachment; no credential entry confirmed.
- **CRITICAL**: User submitted domain credentials, approved MFA prompt (MFA fatigue), or malware execution detected on endpoint.

## 4. Triage and Initial Verification Steps
1. **Analyze RFC 822 Headers**:
   Extract `Return-Path`, `Authentication-Results`, `Received` hops, and originating IP. Check IP against threat reputation feeds.
2. **Inspect Links & Domains in Sandbox**:
   Analyze URLs using safe sandbox tools (e.g., URLScan.io or internal detonation chambers). Check for OAuth consent grants (illicit consent grant attacks).
3. **Determine Scope & Blast Radius**:
   Query email gateway logs via Message ID or Subject hash to identify all recipients across the organization.

## 5. Containment Actions
1. **Global Message Purge**:
   Execute tenant-wide hard purge across all mailboxes for the malicious Message-ID / Subject line.
2. **Domain & IP Blocklist**:
   Block sender domain, originating IP, and destination URL on email gateway, proxy, and DNS filter.
3. **Compromised Account Remediation**:
   If credentials were submitted: immediately reset user password, revoke active refresh tokens/sessions, and reset MFA registrations.

## 6. Eradication and Hardening
- Enforce FIDO2 / WebAuthn phishing-resistant MFA across all accounts.
- Implement strict DMARC enforcement policy (`p=reject`).
- Train employees and submit sample indicators to corporate phishing simulation filters.
