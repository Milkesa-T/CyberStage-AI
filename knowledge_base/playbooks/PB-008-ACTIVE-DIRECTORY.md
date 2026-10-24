# PB-008: Active Directory Kerberos Attacks and DCSync Incident Response Playbook

## 1. Overview and Threat Profile
- **Playbook ID**: PB-008-ACTIVE-DIRECTORY
- **Category**: ACTIVE_DIRECTORY / UNAUTHORIZED_ACCESS / PRIVILEGE_ESCALATION
- **Framework Alignment**: Microsoft Security Incident Management Guide, ANSSI Active Directory Hardening, MITRE ATT&CK T1558 (Steal or Forge Kerberos Tickets: Kerberoasting), T1003.006 (DCSync), T1550.003 (Pass the Ticket)
- **Description**: Operational response procedures for enterprise Windows Domain environments experiencing Kerberoasting, Golden/Silver Ticket forging, LSASS memory credential dumping (Mimikatz), and Directory Replication Service abuse (DCSync).

## 2. Key Indicators of Compromise (IOCs)
- Windows Event ID 4769 (Kerberos Service Ticket Requested) generated in high volumes requesting RC4-HMAC encryption (`Ticket Encryption Type: 0x17`) against service accounts with high privilege.
- Directory Service replication RPC calls (`GetNCChanges` via MS-DRSR) originating from a non-Domain Controller workstation IP (signature of Mimikatz DCSync).
- Kerberos TGT ticket requests with anomalous validity lifetimes (e.g., tickets valid for 10 years, indicating Golden Ticket creation with forged KRBTGT hash).
- Windows Event ID 4740 (User Account Locked Out) triggered across multiple user accounts within seconds (password spraying against Domain Controller).
- Suspicious LSASS memory access events (Sysmon Event ID 10) targeting `lsass.exe` with granted access `0x1010` or `0x1F0FFF`.

## 3. Severity Matrix
- **LOW**: Isolated Kerberos pre-authentication failure (Event ID 4771) on a single workstation during password change.
- **MEDIUM**: Low-volume Kerberoasting requests targeting standard service accounts without domain admin privileges.
- **HIGH**: Kerberoasting activity targeting Tier-0 Domain Admins or sensitive database service accounts (SPNs); suspicious LSASS access flagged on a member server.
- **CRITICAL**: DCSync replication commands executed from any workstation or member server; Golden Ticket authentication detected; Domain Controller memory dumped.

## 4. Triage and Initial Verification Steps
1. **Analyze Kerberos Event ID 4769 Logs**:
   Examine Domain Controller event logs for anomalous service ticket requests:
   Filter for `EventID 4769` where `TicketEncryptionType == 0x17` and `ServiceName != krbtgt`. Identify the client IP and requesting user account.
2. **Verify DCSync Source**:
   Correlate Directory Service access logs (Event ID 4662) for the Extended Right `DS-Replication-Get-Changes-All` (`1131f6aa-9c0e-11d1-a722-00a0c911e4c5`). If the caller is NOT a known Domain Controller computer object, DCSync is confirmed.
3. **Inspect Privileged Group Membership**:
   Audit membership of `Domain Admins`, `Enterprise Admins`, `Schema Admins`, and `Backup Operators` for recently added or unrecognized accounts.
4. **Identify Blast Radius**:
   Determine which tier of assets the compromised account had access to (Tier-0 Domain Controllers, Tier-1 Servers, or Tier-2 Workstations).

## 5. Containment Actions
1. **Isolate Compromised Host from Domain**:
   Immediately isolate the workstation running DCSync or credential-dumping tools using EDR or switch-port disabling to prevent further network pivot.
2. **Execute Mandatory KRBTGT Password Double-Reset**:
   If Golden Ticket creation or DCSync is suspected, initiate the **KRBTGT double-reset procedure**:
   - Reset the `krbtgt` account password via PowerShell (`Reset-KrbTgtPassword.ps1`).
   - Wait for domain replication (typically 4-10 hours depending on topology).
   - Reset the `krbtgt` account password a second time to invalidate all pre-existing Kerberos tickets across the entire forest.
3. **Reset Compromised Service Account Passwords**:
   Force immediate 30+ character AES-256 password resets for all Service Principal Names (SPNs) targeted in Kerberoasting.
4. **Invalidate Stolen NTLM Hashes**:
   Disable or force password reset for all user accounts identified in the DCSync dump log.

## 6. Eradication and Hardening
- Enforce AES-256 Kerberos encryption (`SupportedEncryptionTypes: 0x18`) and disable legacy RC4 encryption across all Active Directory accounts.
- Deploy Microsoft Defender for Identity (MDI) or agent-based AD threat analytics on all Domain Controllers.
- Implement Tiered Administration Architecture (Tier 0, Tier 1, Tier 2) with Privileged Access Workstations (PAWs).
- Enable LSA Protection (`RunAsPPL=1`) and Credential Guard to prevent memory dumping of LSASS credentials by non-system processes.
