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
    name: 'Malware Persistence',
    icon: '🦠',
    title: 'Suspicious PowerShell & Scheduled Task Persistence',
    description: 'Endpoint EDR flagged encoded PowerShell spawning persistence task and outbound beaconing.',
    affected_asset: 'finance-wkst-04',
    source_ip: '185.220.101.5',
    raw_logs: `EventID 4688: Process Creation: powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQ...
EventID 4697: Service/Task Installation: 'WindowsSecurityHealthUpdater' pointing to C:\\Users\\Public\\svchost_updater.exe
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
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!formData.title || formData.title.length < 3) {
      setError('Title must be at least 3 characters.');
      return;
    }
    if (!formData.description || formData.description.length < 10) {
      setError('Description must be at least 10 characters.');
      return;
    }
    if (!formData.raw_logs || formData.raw_logs.length < 10) {
      setError('Raw logs must be at least 10 characters.');
      return;
    }

    setLoading(true);
    setError(null);
    setCheckedSteps({});

    const startTime = performance.now();

    try {
      const response = await fetch(`${API_BASE}/api/v1/incidents/triage`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          title: formData.title,
          description: formData.description,
          raw_logs: formData.raw_logs,
          source_ip: formData.source_ip || null,
          affected_asset: formData.affected_asset || null,
        }),
      });

      const data = await response.json();
      const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);

      if (!response.ok) {
        throw new Error(data.detail || data.message || 'Triage submission failed');
      }

      setAssessment({
        ...data,
        elapsedSeconds: elapsed,
        requestId: response.headers.get('X-Request-ID') || 'N/A',
      });
      showToast(`Triage assessment generated in ${elapsed}s`);
    } catch (err) {
      setError(err.message || 'Network error connecting to CyberSage API');
    } finally {
      setLoading(false);
    }
  };

  const toggleStep = (index) => {
    setCheckedSteps((prev) => ({
      ...prev,
      [index]: !prev[index],
    }));
  };

  const copyMarkdownReport = () => {
    if (!assessment) return;
    const text = `# CyberSage AI — Defensive Incident Triage Report
- **Incident ID:** \`${assessment.incident_id}\`
- **Timestamp:** ${assessment.timestamp}
- **Severity:** **${assessment.suggested_severity}**
- **Category:** \`${assessment.incident_category}\`
- **Affected Asset:** ${formData.affected_asset || 'N/A'}
- **Source IP:** ${formData.source_ip || 'N/A'}

## Executive Summary
${assessment.summary}

## Actionable Containment Steps
${assessment.recommended_steps.map((s, i) => `${i + 1}. [${checkedSteps[i] ? 'x' : ' '}] ${s}`).join('\n')}

## Observable Evidence
${assessment.supporting_evidence.map((e) => `- ${e}`).join('\n')}

## Cited Defensive Playbooks (RAG)
${assessment.source_references.map((r) => `- **${r.playbook_id}**: ${r.playbook_title} (${r.section}) [Similarity: ${(r.similarity_score * 100).toFixed(1)}%]`).join('\n')}

## Uncertainty & Operational Limitations
${assessment.uncertainty_limitations}
`;
    navigator.clipboard.writeText(text);
    showToast('Markdown report copied to clipboard!');
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
    showToast('JSON assessment downloaded');
  };

  return (
    <div>
      {/* Top Navigation */}
      <header className="navbar">
        <div className="brand-wrapper">
          <svg className="brand-logo-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
          </svg>
          <span className="brand-title">CyberSage AI</span>
          <span className="brand-badge">SOC Assistant</span>
        </div>

        <div className="nav-status-items">
          <div className="status-indicator" title={backendHealth ? 'Connected to backend' : 'Backend offline or unreachable'}>
            <div className={`status-dot ${backendHealth ? '' : 'offline'}`} />
            <span>{backendHealth ? `API Online (${backendHealth.environment})` : 'API Offline'}</span>
          </div>
          <div className="status-indicator">
            <span style={{ color: 'var(--cyber-cyan)', fontWeight: 600 }}>RAG + Gemini 2.5</span>
          </div>
        </div>
      </header>

      {/* Main SOC Dashboard */}
      <main className="dashboard-container">
        {/* Left Column: Form Submission */}
        <section className="panel" aria-labelledby="form-heading">
          <div className="panel-header">
            <h1 id="form-heading" className="panel-title">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
              </svg>
              Submit Incident Telemetry
            </h1>
            <button
              id="clear-form-btn"
              type="button"
              className="btn-secondary"
              onClick={handleClear}
              title="Reset all form fields"
            >
              Clear
            </button>
          </div>

          <div className="panel-body">
            {/* Template Selector */}
            <div className="template-bar">
              <span className="template-label">Pre-load Incident Scenario:</span>
              <div className="template-chips">
                {TEMPLATES.map((tmpl) => (
                  <button
                    key={tmpl.name}
                    id={`template-${tmpl.name.toLowerCase().replace(/\s+/g, '-')}`}
                    type="button"
                    className="chip-btn"
                    onClick={() => handleTemplateSelect(tmpl)}
                  >
                    <span>{tmpl.icon}</span>
                    <span>{tmpl.name}</span>
                  </button>
                ))}
              </div>
            </div>

            {error && (
              <div style={{
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid var(--sev-critical-border)',
                color: 'var(--sev-critical-text)',
                padding: '0.75rem 1rem',
                borderRadius: '8px',
                marginBottom: '1.25rem',
                fontSize: '0.85rem'
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
                    Analyzing Telemetry & Retrieving Playbooks...
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
                    Querying ChromaDB vector embeddings & formulating bounded Gemini prompt...
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
                <p style={{ maxWidth: '360px', fontSize: '0.85rem', lineHeight: 1.6 }}>
                  Select an incident scenario from the preset chips on the left, or paste custom raw logs to run an AI-powered defensive triage assessment.
                </p>
              </div>
            )}

            {!loading && assessment && (
              <div id="triage-results-container">
                {/* Header with Severity & Category */}
                <div className="assessment-header">
                  <div className="badges-group">
                    <span id="severity-badge" className={`severity-badge ${assessment.suggested_severity}`}>
                      ● {assessment.suggested_severity} SEVERITY
                    </span>
                    <span id="category-badge" className="category-badge">
                      {assessment.incident_category}
                    </span>
                  </div>

                  <div style={{ fontSize: '0.75rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                    <span>ID: {assessment.incident_id.slice(0, 8)}...</span> | <span>{assessment.elapsedSeconds}s</span>
                  </div>
                </div>

                {/* Executive Summary */}
                <div className="report-section">
                  <h3 className="section-heading">Executive Summary</h3>
                  <div id="incident-summary-text" className="summary-box">
                    {assessment.summary}
                  </div>
                </div>

                {/* Actionable Containment Steps */}
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

                {/* Supporting Observable Evidence */}
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

                {/* Cited Defensive Playbooks (RAG) */}
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

                {/* Operational Limitations */}
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
