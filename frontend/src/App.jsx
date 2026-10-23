import React, { useState, useEffect } from 'react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const TEMPLATES = [
  {
    name: 'SSH Brute Force',
    icon: '🛡️',
    title: 'Massive SSH Brute Force against Bastion Host',
    description: 'High frequency failed password attempts targeting root and service accounts on public edge bastion.',
    affected_asset: 'bastion-01.corp.internal',
    source_ip: '198.51.100.44',
    raw_logs: `Oct 22 10:14:02 bastion-01 sshd[2841]: Failed password for invalid user admin from 198.51.100.44 port 48210 ssh2
Oct 22 10:14:04 bastion-01 sshd[2842]: Failed password for invalid user root from 198.51.100.44 port 48211 ssh2
Oct 22 10:14:07 bastion-01 sshd[2845]: Failed password for invalid user deploy from 198.51.100.44 port 48215 ssh2
Oct 22 10:14:10 bastion-01 sshd[2849]: Failed password for invalid user test from 198.51.100.44 port 48218 ssh2
Oct 22 10:14:12 bastion-01 sshd[2851]: Maximum authentication attempts exceeded for invalid user test from 198.51.100.44 port 48218 ssh2`,
  },
  {
    name: 'Ransomware Attack',
    icon: '⚡',
    title: 'Active Ransomware Outbreak & Shadow Copy Deletion',
    description: 'Finance file share server shows volume shadow deletion and mass file extension renaming to .locked.',
    affected_asset: 'fs-finance-01.corp.internal',
    source_ip: '198.51.100.99',
    raw_logs: `EventID 4688: Process Creation: cmd.exe /c vssadmin delete shadows /all /quiet
Process spawned: C:\\Windows\\Temp\\crypt_payload.exe -dir C:\\FinanceShare
Renaming: C:\\FinanceShare\\Q3_Earnings.xlsx -> Q3_Earnings.xlsx.locked
Renaming: C:\\FinanceShare\\Payroll.docx -> Payroll.docx.locked
Created file: C:\\FinanceShare\\HOW_TO_DECRYPT_FILES.txt
Network connection: Outbound payload transfer to 198.51.100.99:8080`,
  },
  {
    name: 'Spear-Phishing',
    icon: '🎣',
    title: 'Executive Wire Fraud Phishing Campaign',
    description: 'Finance personnel reported suspicious urgent payment request impersonating CFO with external link.',
    affected_asset: 'Exchange-Mailbox-Finance',
    source_ip: '203.0.113.19',
    raw_logs: `Return-Path: <exec-spoofed@finance-approval-portal.xyz>
Authentication-Results: spf=fail (sender IP 203.0.113.19); dkim=none; dmarc=fail
Subject: URGENT: Q3 Executive Wire Transfer Authorization - Immediate Action Required
Header-Message-ID: <4910.20261022@finance-approval-portal.xyz>
Body text snippet: "Please immediately authorize the attached expedited invoice at: https://secure-wire-verify.xyz/login?token=8943"`,
  },
  {
    name: 'SQLi & Cloud SSRF',
    icon: '🌐',
    title: 'Web Application SQL Injection & IMDS SSRF Attempt',
    description: 'Public API gateway detected UNION SELECT injection and AWS metadata service credential harvesting.',
    affected_asset: 'api-gateway-prod',
    source_ip: '198.51.100.77',
    raw_logs: `GET /api/v1/users?id=1' UNION SELECT username,password FROM app_users-- HTTP/1.1
Host: api.cybercorp.io
User-Agent: sqlmap/1.6.4#stable
Follow-up request: GET /proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
Response: 200 OK - length 1420 bytes referencing CVE-2021-44228`,
  },
  {
    name: 'Malware Persistence',
    icon: '🦠',
    title: 'Suspicious PowerShell & Scheduled Task Persistence',
    description: 'Endpoint EDR flagged encoded PowerShell spawning persistence task and outbound beaconing.',
    affected_asset: 'finance-wkst-04',
    source_ip: '185.220.101.5',
    raw_logs: `EventID 4688: Process Creation: powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQ...
EventID 4697: Service/Task Installation: 'WindowsSecurityHealthUpdater' pointing to C:\\Users\\Public\\svchost_updater.exe
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Network Connection: C:\\Users\\Public\\svchost_updater.exe established outbound connection to 185.220.101.5:4444 (State: ESTABLISHED)`,
  },
  {
    name: 'Cloud IAM Leak',
    icon: '☁️',
    title: 'AWS Admin Access Key Activity from Foreign IP',
    description: 'CloudTrail logged administrative IAM calls opening security group 0.0.0.0/0 from unrecognized IP.',
    affected_asset: 'AWS-Production-Account',
    source_ip: '198.18.0.15',
    raw_logs: `"eventVersion": "1.08", "userIdentity": {"type": "IAMUser", "userName": "admin-deployer", "accessKeyId": "AKIAIOSFODNN7EXAMPLE"},
"eventName": "AuthorizeSecurityGroupIngress", "sourceIPAddress": "198.18.0.15",
"requestParameters": {"ipPermissions": [{"ipProtocol": "tcp", "fromPort": 0, "toPort": 65535, "ipRanges": ["0.0.0.0/0"]}]},
"eventName": "CreateAccessKey", "sourceIPAddress": "198.18.0.15"`,
  },
];

export default function App() {
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    affected_asset: '',
    source_ip: '',
    raw_logs: '',
  });

  const [assessment, setAssessment] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [backendHealth, setBackendHealth] = useState(null);
  const [checkedSteps, setCheckedSteps] = useState({});
  const [expandedRollback, setExpandedRollback] = useState({});
  const [toastMessage, setToastMessage] = useState(null);

  // Poll backend health check on mount
  useEffect(() => {
    async function checkHealth() {
      try {
        const res = await fetch(`${API_BASE}/api/v1/health`);
        if (res.ok) {
          const data = await res.json();
          setBackendHealth(data);
        } else {
          setBackendHealth(null);
        }
      } catch (err) {
        setBackendHealth(null);
      }
    }
    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const copyToClipboard = (text, label) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    showToast(`Copied ${label} to clipboard`);
  };

  const handleTemplateSelect = (template) => {
    setFormData({
      title: template.title,
      description: template.description,
      affected_asset: template.affected_asset,
      source_ip: template.source_ip,
      raw_logs: template.raw_logs,
    });
    setError(null);
  };

  const handleClear = () => {
    setFormData({
      title: '',
      description: '',
      affected_asset: '',
      source_ip: '',
      raw_logs: '',
    });
    setAssessment(null);
    setError(null);
    setCheckedSteps({});
    setExpandedRollback({});
  };

  const toggleStep = (index) => {
    setCheckedSteps((prev) => ({
      ...prev,
      [index]: !prev[index],
    }));
  };

  const toggleRollback = (index) => {
    setExpandedRollback((prev) => ({
      ...prev,
      [index]: !prev[index],
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setCheckedSteps({});
    setExpandedRollback({});

    const startTime = performance.now();

    try {
      const payload = {
        title: formData.title.trim(),
        description: formData.description.trim(),
        raw_logs: formData.raw_logs.trim(),
        source_ip: formData.source_ip.trim() || null,
        affected_asset: formData.affected_asset.trim() || null,
      };

      const res = await fetch(`${API_BASE}/api/v1/incidents/triage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Server responded with status ${res.status}`);
      }

      const data = await res.json();
      const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);
      setAssessment({ ...data, elapsedSeconds: elapsed });
      showToast('Incident triage assessment complete');
    } catch (err) {
      setError(err.message || 'Failed to submit incident for triage.');
    } finally {
      setLoading(false);
    }
  };

  const copyMarkdownReport = () => {
    if (!assessment) return;

    let md = `# [CyberSage AI] Incident Triage Report\n\n`;
    md += `**Incident ID:** \`${assessment.incident_id}\`  \n`;
    md += `**Timestamp:** ${assessment.timestamp}  \n`;
    md += `**Severity:** **${assessment.suggested_severity}**  \n`;
    md += `**Category:** ${assessment.incident_category}  \n`;
    if (assessment.confidence_score !== undefined) {
      md += `**Confidence Score:** ${(assessment.confidence_score * 100).toFixed(1)}% | **False Positive Risk:** ${assessment.false_positive_risk}\n\n`;
    }

    if (assessment.sla_deadline) {
      md += `### Response SLAs (Service Level Agreements)\n`;
      md += `- **MTTA Target:** ${assessment.sla_deadline.mtta_minutes} minutes (Deadline: ${assessment.sla_deadline.acknowledge_deadline_utc})\n`;
      md += `- **MTTR Target:** ${assessment.sla_deadline.mttr_minutes} minutes (Deadline: ${assessment.sla_deadline.remediate_deadline_utc})\n`;
      md += `- **Escalation Pathway:** ${assessment.sla_deadline.escalation_tier}\n`;
      if (assessment.sla_deadline.regulatory_breach_window) {
        md += `- **Regulatory Notice:** ${assessment.sla_deadline.regulatory_breach_window}\n`;
      }
      md += `\n`;
    }

    md += `## Executive Summary\n${assessment.summary}\n\n`;

    if (assessment.extracted_iocs && assessment.extracted_iocs.public_ips) {
      md += `## Extracted Indicators of Compromise (IOCs)\n`;
      if (assessment.extracted_iocs.public_ips.length > 0) {
        md += `- **Public IPs:** ${assessment.extracted_iocs.public_ips.join(', ')}\n`;
      }
      if (assessment.extracted_iocs.private_ips.length > 0) {
        md += `- **Private IPs:** ${assessment.extracted_iocs.private_ips.join(', ')}\n`;
      }
      if (assessment.extracted_iocs.defanged_urls.length > 0) {
        md += `- **Defanged URLs:** ${assessment.extracted_iocs.defanged_urls.join(', ')}\n`;
      }
      if (assessment.extracted_iocs.file_hashes.length > 0) {
        md += `- **File Hashes:** ${assessment.extracted_iocs.file_hashes.join(', ')}\n`;
      }
      if (assessment.extracted_iocs.cve_ids.length > 0) {
        md += `- **CVEs:** ${assessment.extracted_iocs.cve_ids.join(', ')}\n`;
      }
      md += `\n`;
    }

    if (assessment.mitre_mapping && assessment.mitre_mapping.tactics) {
      md += `## MITRE ATT&CK Mapping\n`;
      md += `- **Tactics:** ${assessment.mitre_mapping.tactics.join(', ')}\n`;
      md += `- **Techniques:** ${assessment.mitre_mapping.techniques.join(', ')}\n\n`;
    }

    md += `## Actionable Containment Steps\n`;
    assessment.recommended_steps.forEach((s, idx) => {
      md += `${idx + 1}. ${s}\n`;
    });
    md += `\n`;

    if (assessment.remediation_scripts && assessment.remediation_scripts.length > 0) {
      md += `## Executable Remediation Scripts\n`;
      assessment.remediation_scripts.forEach((scr) => {
        md += `### ${scr.platform} — ${scr.action}\n\`\`\`bash\n${scr.commands.join('\n')}\n\`\`\`\n\n`;
      });
    }

    if (assessment.compliance_mappings && assessment.compliance_mappings.length > 0) {
      md += `## Regulatory Compliance Controls\n`;
      assessment.compliance_mappings.forEach((c) => {
        md += `- **${c.framework} [${c.control_id}]:** ${c.title} — ${c.relevance_note}\n`;
      });
      md += `\n`;
    }

    md += `## Observable Telemetry Evidence\n`;
    assessment.supporting_evidence.forEach((ev) => {
      md += `- \`${ev}\`\n`;
    });

    copyToClipboard(md, 'Markdown report');
  };

  const exportJSON = () => {
    if (!assessment) return;
    const blob = new Blob([JSON.stringify(assessment, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cybersage-triage-${assessment.incident_id.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Exported incident assessment JSON');
  };

  const formatUtcTime = (utcStr) => {
    if (!utcStr) return '';
    try {
      const d = new Date(utcStr);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' UTC';
    } catch {
      return utcStr;
    }
  };

  return (
    <div>
      {/* Navbar Header */}
      <nav className="navbar">
        <div className="brand-wrapper">
          <div className="brand-logo-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#050b14" strokeWidth="2.5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" />
            </svg>
          </div>
          <span className="brand-name">CyberSage AI</span>
          <span className="brand-badge">SOC Enterprise</span>
        </div>

        <div className="system-status-group">
          <div className="status-pill">
            <span className={`status-dot ${backendHealth ? 'online' : 'offline'}`} />
            <span>API: {backendHealth ? 'ONLINE' : 'OFFLINE'}</span>
          </div>

          <div className="status-pill">
            <span className={`status-dot ${backendHealth?.vector_store?.count > 0 ? 'online' : 'offline'}`} />
            <span>RAG Playbooks: {backendHealth?.vector_store?.count ?? 0}</span>
          </div>

          <div className="status-pill">
            <span className="status-dot online" />
            <span>Detectors: 7 Active</span>
          </div>
        </div>
      </nav>

      {/* Main Grid */}
      <main className="dashboard-container">
        {/* Left Column: Submission Form */}
        <section className="panel" aria-labelledby="intake-heading">
          <div className="panel-header">
            <h2 id="intake-heading" className="panel-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m5.25 6H12m-3 0h.008v.008H9V18zm0-3h.008v.008H9V15zm0-3h.008v.008H9V12zm0-3h.008v.008H9V9z" />
              </svg>
              Incident Telemetry Intake
            </h2>

            <button
              id="clear-form-btn"
              type="button"
              className="btn-secondary"
              onClick={handleClear}
              title="Clear all fields"
            >
              Clear
            </button>
          </div>

          <div className="panel-body">
            {/* Scenario Preset Chips */}
            <div style={{ marginBottom: '0.6rem' }}>
              <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Enterprise Scenario Presets:
              </span>
            </div>
            <div className="templates-carousel" role="toolbar" aria-label="Scenario Templates">
              {TEMPLATES.map((tmpl, idx) => (
                <button
                  key={idx}
                  type="button"
                  className="template-chip"
                  onClick={() => handleTemplateSelect(tmpl)}
                >
                  <span>{tmpl.icon}</span>
                  <span>{tmpl.name}</span>
                </button>
              ))}
            </div>

            {error && (
              <div style={{
                background: 'rgba(239, 68, 68, 0.15)',
                border: '1px solid rgba(239, 68, 68, 0.4)',
                borderRadius: '8px',
                padding: '0.75rem 1rem',
                color: '#fca5a5',
                fontSize: '0.85rem',
                marginBottom: '1.25rem'
              }}>
                ⚠️ {error}
              </div>
            )}

            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label htmlFor="incident-title-input">
                  Incident Title / Alert Summary <span className="required-star">*</span>
                </label>
                <input
                  id="incident-title-input"
                  type="text"
                  placeholder="e.g., Massive SSH Brute Force against Bastion Host"
                  value={formData.title}
                  onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                  required
                />
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label htmlFor="affected-asset-input">Affected Asset</label>
                  <input
                    id="affected-asset-input"
                    type="text"
                    placeholder="e.g., srv-bastion-01"
                    value={formData.affected_asset}
                    onChange={(e) => setFormData({ ...formData, affected_asset: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="source-ip-input">Source IP Address</label>
                  <input
                    id="source-ip-input"
                    type="text"
                    placeholder="e.g., 198.51.100.44"
                    value={formData.source_ip}
                    onChange={(e) => setFormData({ ...formData, source_ip: e.target.value })}
                  />
                </div>
              </div>

              <div className="form-group">
                <label htmlFor="description-input">
                  Analyst Context & Symptoms <span className="required-star">*</span>
                </label>
                <textarea
                  id="description-input"
                  rows={3}
                  placeholder="Describe observed anomalous symptoms, blast radius, or analyst hypotheses..."
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="raw-logs-input">
                  Raw Log Telemetry (Syslog, CloudTrail, EDR) <span className="required-star">*</span>
                </label>
                <textarea
                  id="raw-logs-input"
                  className="mono-input"
                  rows={7}
                  placeholder="Paste verbatim syslog entries, auth.log lines, Windows Event IDs, or JSON payloads..."
                  value={formData.raw_logs}
                  onChange={(e) => setFormData({ ...formData, raw_logs: e.target.value })}
                  required
                />
                <div className="input-helper">
                  <span>Guarded against prompt injection</span>
                  <span>{formData.raw_logs.length} characters</span>
                </div>
              </div>

              <button
                id="submit-triage-btn"
                type="submit"
                className="btn-primary"
                disabled={loading}
              >
                {loading ? (
                  <>
                    <span className="radar-circle" style={{ width: 16, height: 16, borderWidth: 2 }} />
                    Running Modular Detectors & Playbook RAG...
                  </>
                ) : (
                  <>
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" />
                    </svg>
                    Run AI Incident Triage
                  </>
                )}
              </button>
            </form>
          </div>
        </section>

        {/* Right Column: Triage Assessment Report */}
        <section className="panel" aria-labelledby="report-heading">
          <div className="panel-header">
            <h2 id="report-heading" className="panel-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
              </svg>
              Triage Assessment Report
            </h2>

            {assessment && (
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button
                  id="copy-markdown-btn"
                  type="button"
                  className="btn-secondary"
                  onClick={copyMarkdownReport}
                  title="Copy full report as Markdown"
                >
                  Copy MD
                </button>
                <button
                  id="export-json-btn"
                  type="button"
                  className="btn-secondary"
                  onClick={exportJSON}
                  title="Export raw JSON"
                >
                  Export JSON
                </button>
              </div>
            )}
          </div>

          <div className="panel-body">
            {loading && (
              <div className="loading-scanner">
                <div className="radar-circle" />
                <div style={{ textAlign: 'center' }}>
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#f1f5f9' }}>
                    Correlating Telemetry with Knowledge Base
                  </h3>
                  <p style={{ fontSize: '0.85rem', color: '#94a3b8', marginTop: '0.25rem' }}>
                    Executing IOC extractors, modular threat detectors & ChromaDB embeddings...
                  </p>
                </div>
              </div>
            )}

            {!loading && !assessment && (
              <div className="empty-state">
                <svg className="empty-state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.25-8.25-3.286zm0 13.036h.008v.008H12v-.008z" />
                </svg>
                <h3 style={{ color: '#cbd5e1', fontSize: '1.05rem', fontWeight: 600, marginBottom: '0.5rem' }}>
                  Awaiting Incident Telemetry
                </h3>
                <p style={{ maxWidth: '380px', fontSize: '0.85rem', lineHeight: 1.6 }}>
                  Select an enterprise incident preset on the left or paste raw logs to execute multi-vector threat detection, SLA deadlines, and automated remediation generation.
                </p>
              </div>
            )}

            {!loading && assessment && (
              <div id="triage-results-container">
                {/* Header with Severity, Category & Confidence */}
                <div className="assessment-header">
                  <div className="badges-group">
                    <span id="severity-badge" className={`severity-badge ${assessment.suggested_severity}`}>
                      ● {assessment.suggested_severity} SEVERITY
                    </span>
                    <span id="category-badge" className="category-badge">
                      {assessment.incident_category}
                    </span>
                    {assessment.confidence_score !== undefined && (
                      <span className="meta-badge" title="Ensemble Detection Confidence">
                        🎯 {(assessment.confidence_score * 100).toFixed(0)}% Conf.
                      </span>
                    )}
                    {assessment.false_positive_risk && (
                      <span className={`meta-badge risk-${assessment.false_positive_risk.toLowerCase()}`}>
                        FP Risk: {assessment.false_positive_risk}
                      </span>
                    )}
                  </div>

                  <div style={{ fontSize: '0.75rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                    <span>ID: {assessment.incident_id.slice(0, 8)}...</span> | <span>{assessment.elapsedSeconds}s</span>
                  </div>
                </div>

                {/* 1. SLA Deadlines & Escalation Pathway */}
                {assessment.sla_deadline && (
                  <div className="sla-card">
                    <div className="sla-header">
                      <div className="sla-title">
                        <span>⏱️ Enterprise Response SLAs</span>
                      </div>
                      <span className="sla-escalation-badge">
                        🚨 {assessment.sla_deadline.escalation_tier}
                      </span>
                    </div>

                    <div className="sla-grid">
                      <div className="sla-box">
                        <div className="sla-box-label">Acknowledge SLA (MTTA)</div>
                        <div className="sla-box-value">{assessment.sla_deadline.mtta_minutes} min</div>
                        <div className="sla-box-time">Target: {formatUtcTime(assessment.sla_deadline.acknowledge_deadline_utc)}</div>
                      </div>

                      <div className="sla-box">
                        <div className="sla-box-label">Remediation SLA (MTTR)</div>
                        <div className="sla-box-value">{assessment.sla_deadline.mttr_minutes} min</div>
                        <div className="sla-box-time">Target: {formatUtcTime(assessment.sla_deadline.remediate_deadline_utc)}</div>
                      </div>
                    </div>

                    {assessment.sla_deadline.regulatory_breach_window && (
                      <div className="regulatory-banner">
                        <span>⚠️</span>
                        <span>{assessment.sla_deadline.regulatory_breach_window}</span>
                      </div>
                    )}
                  </div>
                )}

                {/* 2. Forensic Indicators of Compromise (IOC Vault) */}
                {assessment.extracted_iocs && (
                  <div className="report-section">
                    <h3 className="section-heading">
                      <span>🔍 Forensic Indicators of Compromise (IOC Vault)</span>
                    </h3>
                    <div className="ioc-vault-grid">
                      {assessment.extracted_iocs.public_ips?.length > 0 && (
                        <div className="ioc-category-box">
                          <div className="ioc-category-title">
                            <span>Hostile External IPs (WAN)</span>
                            <span style={{ color: '#ef4444' }}>● External</span>
                          </div>
                          <div className="ioc-tag-wrap">
                            {assessment.extracted_iocs.public_ips.map((ip, i) => (
                              <button
                                key={i}
                                type="button"
                                className="ioc-tag public-ip"
                                onClick={() => copyToClipboard(ip, `IP ${ip}`)}
                                title="Click to copy IP"
                              >
                                {ip} 📋
                              </button>
                            ))}
                          </div>
                        </div>
                      )}

                      {assessment.extracted_iocs.private_ips?.length > 0 && (
                        <div className="ioc-category-box">
                          <div className="ioc-category-title">
                            <span>Internal Network IPs (RFC 1918)</span>
                            <span style={{ color: '#60a5fa' }}>● Lateral</span>
                          </div>
                          <div className="ioc-tag-wrap">
                            {assessment.extracted_iocs.private_ips.map((ip, i) => (
                              <button
                                key={i}
                                type="button"
                                className="ioc-tag private-ip"
                                onClick={() => copyToClipboard(ip, `IP ${ip}`)}
                                title="Click to copy IP"
                              >
                                {ip} 📋
                              </button>
                            ))}
                          </div>
                        </div>
                      )}

                      {assessment.extracted_iocs.defanged_urls?.length > 0 && (
                        <div className="ioc-category-box">
                          <div className="ioc-category-title">
                            <span>Defanged URLs (Safe View)</span>
                          </div>
                          <div className="ioc-tag-wrap">
                            {assessment.extracted_iocs.defanged_urls.map((url, i) => (
                              <button
                                key={i}
                                type="button"
                                className="ioc-tag"
                                onClick={() => copyToClipboard(url, 'URL')}
                                title="Click to copy URL"
                              >
                                {url} 📋
                              </button>
                            ))}
                          </div>
                        </div>
                      )}

                      {assessment.extracted_iocs.file_hashes?.length > 0 && (
                        <div className="ioc-category-box">
                          <div className="ioc-category-title">
                            <span>File Hashes (SHA256 / MD5)</span>
                          </div>
                          <div className="ioc-tag-wrap">
                            {assessment.extracted_iocs.file_hashes.map((hash, i) => (
                              <button
                                key={i}
                                type="button"
                                className="ioc-tag hash"
                                onClick={() => copyToClipboard(hash, 'Hash')}
                                title="Click to copy Hash"
                              >
                                {hash.slice(0, 16)}... 📋
                              </button>
                            ))}
                          </div>
                        </div>
                      )}

                      {assessment.extracted_iocs.cve_ids?.length > 0 && (
                        <div className="ioc-category-box">
                          <div className="ioc-category-title">
                            <span>Referenced CVEs</span>
                          </div>
                          <div className="ioc-tag-wrap">
                            {assessment.extracted_iocs.cve_ids.map((cve, i) => (
                              <button
                                key={i}
                                type="button"
                                className="ioc-tag cve"
                                onClick={() => copyToClipboard(cve, cve)}
                                title="Click to copy CVE"
                              >
                                {cve} 📋
                              </button>
                            ))}
                          </div>
                        </div>
                      )}

                      {assessment.extracted_iocs.cloud_identities?.length > 0 && (
                        <div className="ioc-category-box">
                          <div className="ioc-category-title">
                            <span>Cloud Identities / IAM Keys</span>
                          </div>
                          <div className="ioc-tag-wrap">
                            {assessment.extracted_iocs.cloud_identities.map((id, i) => (
                              <button
                                key={i}
                                type="button"
                                className="ioc-tag cve"
                                onClick={() => copyToClipboard(id, 'Cloud Identity')}
                                title="Click to copy"
                              >
                                {id} 📋
                              </button>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* 3. MITRE ATT&CK Attribution Matrix */}
                {assessment.mitre_mapping && (assessment.mitre_mapping.tactics?.length > 0 || assessment.mitre_mapping.techniques?.length > 0) && (
                  <div className="mitre-matrix-card">
                    <div className="section-heading" style={{ color: '#d8b4fe', marginBottom: '0.75rem' }}>
                      <span>🎯 MITRE ATT&CK Attribution Matrix</span>
                    </div>
                    <div className="mitre-tags-wrapper">
                      {assessment.mitre_mapping.tactics?.length > 0 && (
                        <div className="mitre-tactic-row">
                          <span className="mitre-label">TACTICS:</span>
                          {assessment.mitre_mapping.tactics.map((t, idx) => (
                            <span key={idx} className="mitre-badge">
                              {t}
                            </span>
                          ))}
                        </div>
                      )}

                      {assessment.mitre_mapping.techniques?.length > 0 && (
                        <div className="mitre-tactic-row">
                          <span className="mitre-label">TECHNIQUES:</span>
                          {assessment.mitre_mapping.techniques.map((tech, idx) => (
                            <span key={idx} className="mitre-tech-badge">
                              {tech}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* 4. Executive Summary */}
                <div className="report-section">
                  <h3 className="section-heading">Executive Summary</h3>
                  <div id="incident-summary-text" className="summary-box">
                    {assessment.summary}
                  </div>
                </div>

                {/* 5. Executable Remediation Shell Scripts */}
                {assessment.remediation_scripts && assessment.remediation_scripts.length > 0 && (
                  <div className="report-section">
                    <h3 className="section-heading">
                      <span>⚡ Executable Remediation Scripts (Copy-Paste Ready)</span>
                    </h3>
                    {assessment.remediation_scripts.map((script, idx) => (
                      <div key={idx} className="terminal-card">
                        <div className="terminal-header">
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                            <div className="terminal-dots">
                              <span className="terminal-dot red" />
                              <span className="terminal-dot yellow" />
                              <span className="terminal-dot green" />
                            </div>
                            <span className="terminal-title">
                              {script.platform} — {script.action}
                            </span>
                          </div>

                          <button
                            type="button"
                            className="btn-secondary"
                            onClick={() => copyToClipboard(script.commands.join('\n'), `${script.platform} commands`)}
                          >
                            Copy Commands
                          </button>
                        </div>

                        <div className="terminal-body">
                          {script.commands.map((cmd, i) => (
                            <div key={i} className={cmd.startsWith('#') ? 'terminal-comment' : ''}>
                              {cmd}
                            </div>
                          ))}
                        </div>

                        {script.rollback_commands && script.rollback_commands.length > 0 && (
                          <div>
                            <button
                              type="button"
                              className="rollback-toggle-btn"
                              onClick={() => toggleRollback(idx)}
                            >
                              <span>{expandedRollback[idx] ? '▼ Hide Rollback' : '▶ Show Rollback Commands'}</span>
                            </button>
                            {expandedRollback[idx] && (
                              <div className="terminal-body" style={{ borderTop: '1px solid rgba(255,255,255,0.08)', background: 'rgba(0,0,0,0.7)' }}>
                                <div className="terminal-comment"># Rollback Commands (if benign false positive):</div>
                                {script.rollback_commands.map((cmd, i) => (
                                  <div key={i}>{cmd}</div>
                                ))}
                              </div>
                            )}
                          </div>
                        )}

                        {script.safe_mode_note && (
                          <div className="safe-mode-callout">
                            ⚠️ {script.safe_mode_note}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {/* 6. Regulatory & Security Compliance Controls */}
                {assessment.compliance_mappings && assessment.compliance_mappings.length > 0 && (
                  <div className="report-section">
                    <h3 className="section-heading">
                      <span>🏛️ Regulatory Compliance & Audit Controls</span>
                    </h3>
                    <div className="compliance-cards-grid">
                      {assessment.compliance_mappings.map((comp, idx) => (
                        <div key={idx} className="compliance-box">
                          <div className="compliance-box-top">
                            <span className="compliance-framework-pill">{comp.framework}</span>
                            <span className="compliance-control-id">{comp.control_id}</span>
                          </div>
                          <div className="compliance-title">{comp.title}</div>
                          <div className="compliance-desc">{comp.description}</div>
                          <div className="compliance-relevance">
                            <strong>Audit Relevance:</strong> {comp.relevance_note}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 7. Actionable Containment Steps */}
                <div className="report-section">
                  <h3 className="section-heading">
                    Actionable Containment Steps ({Object.values(checkedSteps).filter(Boolean).length}/{assessment.recommended_steps.length})
                  </h3>
                  <ul className="steps-list">
                    {assessment.recommended_steps.map((step, idx) => (
                      <li key={idx} className="step-item">
                        <input
                          type="checkbox"
                          id={`step-check-${idx}`}
                          className="step-checkbox"
                          checked={Boolean(checkedSteps[idx])}
                          onChange={() => toggleStep(idx)}
                        />
                        <label
                          htmlFor={`step-check-${idx}`}
                          className={`step-text ${checkedSteps[idx] ? 'checked' : ''}`}
                          style={{ cursor: 'pointer', margin: 0, fontWeight: 'normal', color: 'inherit' }}
                        >
                          {step}
                        </label>
                      </li>
                    ))}
                  </ul>
                </div>

                {/* 8. Supporting Observable Evidence */}
                <div className="report-section">
                  <h3 className="section-heading">Observable Telemetry Evidence</h3>
                  <ul className="evidence-list">
                    {assessment.supporting_evidence.map((ev, idx) => (
                      <li key={idx} className="evidence-item">
                        {ev}
                      </li>
                    ))}
                  </ul>
                </div>

                {/* 9. Cited Defensive Playbooks (RAG Grounding) */}
                <div className="report-section">
                  <h3 className="section-heading">
                    Retrieved Defensive Playbooks (RAG Grounding)
                  </h3>
                  {assessment.source_references && assessment.source_references.length > 0 ? (
                    assessment.source_references.map((ref, idx) => (
                      <div key={idx} className="playbook-card">
                        <div className="playbook-header">
                          <span className="playbook-title">
                            📖 {ref.playbook_id}: {ref.playbook_title} — <em style={{ color: '#94a3b8' }}>{ref.section}</em>
                          </span>
                          <span className="match-score">
                            {(ref.similarity_score * 100).toFixed(0)}% match
                          </span>
                        </div>
                        <div className="playbook-excerpt">
                          {ref.excerpt}
                        </div>
                      </div>
                    ))
                  ) : (
                    <p style={{ fontSize: '0.8rem', color: '#64748b' }}>
                      No direct playbook matches found above similarity threshold.
                    </p>
                  )}
                </div>

                {/* 10. Operational Limitations */}
                {assessment.uncertainty_limitations && (
                  <div className="report-section">
                    <h3 className="section-heading">Operational Uncertainty & Limitations</h3>
                    <p style={{ fontSize: '0.8rem', color: '#94a3b8', background: 'rgba(255,255,255,0.02)', padding: '0.75rem', borderRadius: '6px' }}>
                      ℹ️ {assessment.uncertainty_limitations}
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>
        </section>
      </main>

      {/* Floating Toast Notification */}
      {toastMessage && (
        <div className="toast" role="status">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--cyber-cyan)" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
          </svg>
          <span>{toastMessage}</span>
        </div>
      )}
    </div>
  );
}
