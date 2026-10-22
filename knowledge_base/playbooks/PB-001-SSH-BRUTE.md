# PB-001: SSH Brute Force and Credential Stuffing Response Playbook

## 1. Overview and Threat Profile
- **Playbook ID**: PB-001-SSH-BRUTE
- **Category**: BRUTE_FORCE / UNAUTHORIZED_ACCESS
- **Description**: Guidance for detecting, triaging, and responding to high-volume automated password guessing, dictionary attacks, and credential stuffing targeting SSH (port 22) and secure remote access gateways.

## 2. Key Indicators of Compromise (IOCs)
- Bursts of authentication failures in `/var/log/auth.log` or `/var/log/secure` containing `Failed password for ... from <SOURCE_IP>`.
- Repeated attempts across common administrative usernames (`root`, `admin`, `test`, `ubuntu`, `postgres`).
- Multiple failed attempts followed within seconds or minutes by `Accepted password` or `Accepted publickey` from the same unauthorized source IP.
- Unusual spike in inbound TCP connections on port 22 or non-standard SSH ports.

## 3. Severity Matrix
- **LOW**: Isolated failed attempts (< 10 in 1 hour) from common scanner IPs with no matching valid usernames.
- **MEDIUM**: Sustained brute-force attempts (> 50 in 10 minutes) targeting invalid accounts; no successful logins recorded.
- **HIGH**: Sustained brute force (> 100 attempts) targeting valid system accounts or service accounts; no successful login confirmed yet.
- **CRITICAL**: Any brute-force activity that concludes with a successful authentication (`Accepted password` / `Accepted publickey`) from an external or anomalous IP address.

## 4. Triage and Initial Verification Steps
1. **Analyze Frequency and Target Accounts**:
   Inspect auth logs to calculate failure rate and determine whether attacks target generic dictionaries or existing internal usernames.
2. **Determine Authentication Outcome**:
   Search logs for any `Accepted` entries from the offending source IP:
   `grep "<SOURCE_IP>" /var/log/auth.log | grep -E "Accepted|session opened"`
3. **Check Active Sessions**:
   Run `who`, `w`, or `last -n 20` to verify if an active session was spawned by the suspicious IP.

## 5. Containment Actions
1. **Immediate Firewall Block**:
   Drop inbound traffic from the source IP using host firewalls (e.g., `iptables -A INPUT -s <SOURCE_IP> -j DROP`) or cloud Network Security Groups (NSGs).
2. **Terminate Active Sessions**:
   If an unauthorized session is active, terminate the process (`pkill -u <SUSPICIOUS_USER>`) and close the SSH tunnel.
3. **Account Locking & Credential Revocation**:
   Lock the compromised account (`passwd -l <USERNAME>`) and invalidate associated authorized keys in `~/.ssh/authorized_keys`.

## 6. Eradication and Hardening
- Enforce public key authentication only (`PasswordAuthentication no` in `/etc/ssh/sshd_config`).
- Disable root login over SSH (`PermitRootLogin no`).
- Deploy brute-force mitigation tools such as Fail2ban or CrowdSec.
- Restrict SSH access behind an IP-allowlisted VPN or bastion host.
