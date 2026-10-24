# PB-005: Ransomware Outbreak and Destructive Malware Incident Response Playbook

## 1. Overview and Threat Profile
- **Playbook ID**: PB-005-RANSOMWARE
- **Category**: RANSOMWARE / DATA_EXFILTRATION / MALWARE
- **Framework Alignment**: NIST SP 800-61r2, CISA Ransomware Guide, MITRE ATT&CK T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), T1048 (Exfiltration Over Alternative Protocol)
- **Description**: Rapid containment, isolation, eradication, and forensic recovery guidance for enterprise environments experiencing active ransomware encryption, volume shadow copy tampering, or destructive wiper execution.

## 2. Key Indicators of Compromise (IOCs)
- Execution of commands designed to inhibit recovery: `vssadmin delete shadows /all /quiet`, `wmic shadowcopy delete`, `wbadmin delete catalog`, or `bcdedit /set {default} bootstatuspolicy ignoreallfailures`.
- Rapid, high-volume file rename operations appending suspicious extensions (e.g., `.locked`, `.encrypted`, `.ransom`, `.wncry`).
- Creation of ransom note files (`HOW_TO_DECRYPT.txt`, `README_DECRYPT.txt`, `YOUR_FILES_ARE_ENCRYPTED.html`) in user home and network shared directories.
- Mass termination of database, backup, and hypervisor services (`net stop MSSQLSERVER`, `net stop VeeamBackupSvc`).
- High-volume outbound data transfers over atypical protocols or to anonymous file storage prior to encryption (double extortion).

## 3. Severity Matrix
- **LOW**: Detection of dormant, unexecuted ransomware binary quarantined by endpoint EDR without execution.
- **MEDIUM**: Ransomware loader identified on a single non-critical workstation; execution blocked prior to shadow copy tampering or lateral spread.
- **HIGH**: Active encryption confirmed on a single workstation or staging server; network isolation verified; no file share or domain controller involvement.
- **CRITICAL**: Active encryption on database servers, domain controllers, virtualization hosts, or multi-host lateral propagation; volume shadows deleted; double extortion observed.

## 4. Triage and Initial Verification Steps
1. **Identify Patient Zero & Blast Radius**:
   Query SIEM/EDR telemetry for the initial execution timestamp of `vssadmin` or suspicious renames. Identify originating IP, user token, and infected hostname.
2. **Determine Encryption Scope**:
   Inspect shared storage arrays (SMB/NFS) for locked files to distinguish local host compromise from network-wide enterprise storage compromise.
3. **Verify Shadow Copy Status**:
   On Windows hosts: `vssadmin list shadows` or `Get-WmiObject Win32_ShadowCopy`. On Linux: check snapshot status on LVM/ZFS/Btrfs pools.
4. **Evaluate Data Exfiltration Evidence**:
   Inspect firewall and proxy connection logs for outbound transfers exceeding normal baseline (> 100 MB) in the 72 hours preceding encryption.

## 5. Containment Actions
1. **Emergency Physical and Network Quarantine**:
   Immediately isolate all suspected hosts from the local network segment. Disconnect physical ethernet cables or issue EDR network isolation commands. Do NOT reboot the machines (preserves RAM encryption keys).
2. **Disable Compromised Service & Admin Accounts**:
   Immediately disable user accounts and service principals associated with the active ransomware process to prevent further lateral authentication.
3. **Block Command-and-Control (C2) Infrastructure**:
   Blackhole destination IPs and sinkhole DNS domains identified in C2 beaconing at the perimeter firewall and recursive DNS resolvers.
4. **Quarantine Shared Storage & Backups**:
   Disconnect network-attached backup storage and set immutable S3 backup vaults to read-only mode to prevent attackers from purging archives.

## 6. Eradication and Forensic Recovery
1. **Capture Volatile Memory**:
   Prior to system shutdown, capture full RAM images (`DumpIt` / `LiME`) for potential plaintext cryptographic key extraction.
2. **Identify Ransomware Family & Decryptor Availability**:
   Extract sample ransom note and encrypted file header. Cross-reference with NoMoreRansom.org and CISA threat databases for known decryption tools.
3. **Validate Air-Gapped Clean Backups**:
   Verify integrity of offline, cold, or immutable backups created prior to the estimated initial access timestamp before initiating any restore.
4. **Activate Legal, Executive & Regulatory Reporting**:
   Activate legal and compliance response protocols. If PII or healthcare data was impacted, initiate the mandatory GDPR Article 33 72-hour notification clock and HIPAA breach evaluation.
