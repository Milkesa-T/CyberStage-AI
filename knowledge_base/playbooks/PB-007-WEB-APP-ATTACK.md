# PB-007: Web Application Exploitation (SQLi, SSRF, XSS) Response Playbook

## 1. Overview and Threat Profile
- **Playbook ID**: PB-007-WEB-APP-ATTACK
- **Category**: WEB_APPLICATION_ATTACK / UNAUTHORIZED_ACCESS / DATA_EXFILTRATION
- **Framework Alignment**: OWASP Top 10 (A01: Broken Access Control, A03: Injection, A10: SSRF), PCI-DSS v4.0 Requirement 6.4, MITRE ATT&CK T1190 (Exploit Public-Facing Application), T1059.007 (JavaScript Injection)
- **Description**: Incident response guidance for attacks targeting public web applications and APIs, including SQL injection, blind injection, reflected/stored XSS, Server-Side Request Forgery against cloud metadata, and directory traversal.

## 2. Key Indicators of Compromise (IOCs)
- HTTP request logs showing database evasion sequences: `UNION SELECT`, `' OR '1'='1`, `information_schema.tables`, `WAITFOR DELAY`, or `SLEEP(5)`.
- Request URLs or proxy parameters containing loopback addresses or cloud metadata IPs: `http://169.254.169.254/latest/meta-data/` or `http://localhost:8080/admin`.
- Script tags or event handlers in HTTP GET/POST parameters: `<script>`, `javascript:`, `onerror=alert()`, or `document.cookie`.
- Path traversal sequences in URI paths or filename query parameters: `../../etc/passwd`, `..\\winnt\\win.ini`, or `%2e%2e%2f`.
- Web Application Firewall (WAF) rule trigger bursts from automated scanners (`sqlmap`, `nikto`, `acunetix`, `nuclei`).

## 3. Severity Matrix
- **LOW**: Low-volume automated scanner probes blocked by edge WAF with HTTP 403 Forbidden; no backend application error logs.
- **MEDIUM**: Reflected XSS payloads detected in URL query strings; payloads escaped by modern web frameworks without client execution.
- **HIGH**: SQL injection payloads producing database syntax errors (HTTP 500) or differential response delays; possible partial table enumeration.
- **CRITICAL**: Successful SQL injection extracting customer database records, PII, or password hashes; SSRF confirmed accessing cloud credentials via metadata API.

## 4. Triage and Initial Verification Steps
1. **Analyze Web Server Access & Error Logs**:
   Correlate client IP, HTTP status code, and response payload byte size. Look for large response sizes following `UNION SELECT` attempts that indicate data exfiltration.
2. **Inspect Database Query Logs**:
   Search backend database query logs (PostgreSQL, MySQL, MSSQL) for unauthorized queries containing `information_schema`, `sysobjects`, or multi-statement injections (`DROP`, `ALTER`).
3. **Check SSRF Target Reachability**:
   Determine whether the application endpoint allows outbound HTTP calls and whether network egress filtering prevents connections to `169.254.169.254` and RFC 1918 addresses.
4. **Determine User Session Context**:
   Identify whether the request was authenticated or unauthenticated. Review user session IDs to determine if administrative accounts were hijacked.

## 5. Containment Actions
1. **WAF IP Drop & Custom Virtual Patching**:
   Immediately block the offending source IP or ASN at Cloudflare/AWS WAF/Akamai edge layer. Deploy a custom regex rule to drop matching URI parameter signatures.
2. **Disable Vulnerable Endpoints**:
   If an application patch cannot be deployed immediately, temporarily route traffic for the affected URI path to a maintenance 503 response.
3. **Rotate Potentially Exposed Credentials**:
   If SSRF or SQL injection occurred, rotate all backend database passwords, application secret keys, and cloud IAM role credentials immediately.
4. **Invalidate Active User Sessions**:
   If session tokens were exposed via XSS or database exfiltration, invalidate all active session tokens across Redis/database session stores.

## 6. Eradication and Hardening
- Enforce parameterized queries (prepared statements) across all ORMs and raw SQL queries; eliminate dynamic string concatenation.
- Implement strict input validation using allowlists and schema enforcement (e.g., Pydantic, Zod) on all API endpoints.
- Configure Content Security Policy (CSP) headers (`default-src 'self'`) to neutralize reflected and stored Cross-Site Scripting.
- Block access to IMDSv1 by requiring IMDSv2 token headers across all cloud workloads.
