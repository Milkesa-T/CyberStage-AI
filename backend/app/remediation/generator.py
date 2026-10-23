"""
CyberSage AI — Executable Remediation Script Generator

Generates parameterized, copy-paste ready defensive containment commands
tailored to the incident category, severity, and extracted IOCs.

SUPPORTED PLATFORMS & ACTIONS:
1. Linux (iptables & ufw) — Host & perimeter firewall IP blocking.
2. Windows PowerShell — Windows Defender Firewall inbound drop rules.
3. AWS CLI — IAM key deactivation & security group ingress revocation.
4. DNS Sinkholing — Domain null-routing for C2 and phishing links.
5. Endpoint Containment (EDR) — Rapid host network isolation for malware/ransomware.
"""

from typing import Optional
from app.schemas.incident import (
    ExtractedIOCs,
    IncidentCategory,
    IncidentSeverity,
    RemediationScript,
)


class RemediationGenerator:
    """
    Generates actionable remediation and containment command sequences for SOC analysts.
    """

    def generate(
        self,
        category: IncidentCategory,
        severity: IncidentSeverity,
        iocs: ExtractedIOCs,
        affected_asset: Optional[str] = None,
    ) -> list[RemediationScript]:
        """
        Produce a list of platform-tailored RemediationScript objects.
        """
        scripts: list[RemediationScript] = []
        target_ips = iocs.public_ips or iocs.ipv4_addresses[:2]

        # ======================================================================
        # 1. Linux Firewall IP Block (iptables & ufw)
        # ======================================================================
        if target_ips:
            primary_ip = target_ips[0]
            scripts.append(
                RemediationScript(
                    platform="Linux (iptables / ufw)",
                    action=f"Block malicious traffic from hostile IP {primary_ip}",
                    commands=[
                        f"# Drop all inbound packets from hostile source IP {primary_ip}",
                        f"sudo iptables -I INPUT 1 -s {primary_ip} -j DROP",
                        f"# If using UFW (Ubuntu/Debian firewall):",
                        f"sudo ufw insert 1 deny from {primary_ip} to any",
                        f"# Save rules across reboots:",
                        "sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null",
                    ],
                    rollback_commands=[
                        f"sudo iptables -D INPUT -s {primary_ip} -j DROP",
                        f"sudo ufw delete deny from {primary_ip} to any",
                    ],
                    safe_mode_note="Requires root / sudo privileges. Verify IP is not an internal gateway before applying.",
                )
            )

        # ======================================================================
        # 2. Windows Defender Firewall (PowerShell)
        # ======================================================================
        if target_ips:
            primary_ip = target_ips[0]
            rule_name = f"CyberSage-Block-{primary_ip.replace('.', '_')}"
            scripts.append(
                RemediationScript(
                    platform="Windows (PowerShell)",
                    action=f"Create inbound block rule in Windows Defender Firewall for {primary_ip}",
                    commands=[
                        f"# Block inbound connections from {primary_ip} across all profiles",
                        f'New-NetFirewallRule -DisplayName "{rule_name}" `',
                        f'    -Direction Inbound `',
                        f'    -Action Block `',
                        f'    -RemoteAddress "{primary_ip}" `',
                        f'    -Description "Automated containment by CyberSage AI for incident triage"',
                    ],
                    rollback_commands=[
                        f'Remove-NetFirewallRule -DisplayName "{rule_name}"',
                    ],
                    safe_mode_note="Run from an elevated (Administrator) PowerShell session.",
                )
            )

        # ======================================================================
        # 3. Cloud Containment (AWS CLI)
        # ======================================================================
        if iocs.cloud_identities or category == IncidentCategory.CLOUD_INFRASTRUCTURE:
            cloud_key = None
            for ident in iocs.cloud_identities:
                if ident.startswith(("AKIA", "ASIA")):
                    cloud_key = ident
                    break
            cloud_key = cloud_key or "AKIA_COMPROMISED_KEY_ID"

            scripts.append(
                RemediationScript(
                    platform="AWS CLI",
                    action=f"Deactivate exposed IAM Access Key and attach quarantine policy ({cloud_key})",
                    commands=[
                        f"# Immediately disable the compromised access key",
                        f"aws iam update-access-key --access-key-id {cloud_key} --status Inactive",
                        f"# Attach explicit Deny-All quarantine boundary policy",
                        f"aws iam attach-user-policy --user-name <COMPROMISED_USERNAME> --policy-arn arn:aws:iam::aws:policy/AWSDenyAll",
                        f"# Terminate all active IAM session tokens",
                        f"aws iam delete-login-profile --user-name <COMPROMISED_USERNAME> 2>/dev/null || true",
                    ],
                    rollback_commands=[
                        f"aws iam update-access-key --access-key-id {cloud_key} --status Active",
                        f"aws iam detach-user-policy --user-name <COMPROMISED_USERNAME> --policy-arn arn:aws:iam::aws:policy/AWSDenyAll",
                    ],
                    safe_mode_note="Requires AWS Admin / IAM permissions with AWS_REGION set.",
                )
            )

        # ======================================================================
        # 4. DNS Sinkholing / Domain Block
        # ======================================================================
        if iocs.domains:
            target_domain = iocs.domains[0]
            scripts.append(
                RemediationScript(
                    platform="DNS Sinkhole (RPZ / Local DNS)",
                    action=f"Null-route malicious domain {target_domain}",
                    commands=[
                        f"# Null-route {target_domain} in /etc/hosts (emergency local containment):",
                        f'echo "0.0.0.0 {target_domain}" | sudo tee -a /etc/hosts',
                        f"# If using Pi-hole or local DNS filter:",
                        f"pihole -b {target_domain}",
                        f"# BIND Response Policy Zone (RPZ) record entry:",
                        f"{target_domain} CNAME .",
                    ],
                    rollback_commands=[
                        f"sudo sed -i '/{target_domain}/d' /etc/hosts",
                        f"pihole -b -d {target_domain}",
                    ],
                    safe_mode_note="Sinkholing blocks all subsequent resolution across hosts consuming this DNS server.",
                )
            )

        # ======================================================================
        # 5. Endpoint Isolation (Malware & Ransomware containment)
        # ======================================================================
        if (
            category in (IncidentCategory.MALWARE, IncidentCategory.RANSOMWARE)
            or severity == IncidentSeverity.CRITICAL
        ):
            target_host = affected_asset or "affected-host"
            scripts.append(
                RemediationScript(
                    platform="EDR / Endpoint Isolation",
                    action=f"Isolate {target_host} from network to stop lateral spread and encryption",
                    commands=[
                        f"# Linux Emergency Network Cut (Preserves loopback for local forensics):",
                        "sudo iptables -P INPUT DROP && sudo iptables -P OUTPUT DROP && sudo iptables -A INPUT -i lo -j ACCEPT && sudo iptables -A OUTPUT -o lo -j ACCEPT",
                        f"# CrowdStrike Falcon EDR CLI isolation command (if installed):",
                        f"falconctl isolate --host-id <AGENT_ID>",
                        f"# Microsoft Defender for Endpoint PowerShell isolation:",
                        f"Set-MpPreference -DisableRealtimeMonitoring $false",
                    ],
                    rollback_commands=[
                        "sudo iptables -P INPUT ACCEPT && sudo iptables -P OUTPUT ACCEPT",
                        "falconctl un-isolate --host-id <AGENT_ID>",
                    ],
                    safe_mode_note="WARNING: Network isolation will terminate active SSH / RDP sessions. Use console access.",
                )
            )

        return scripts
