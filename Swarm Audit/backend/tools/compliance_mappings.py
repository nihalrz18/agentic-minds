"""
Compliance mapping data and lookup utilities for SwarmAudit.
Maps OWASP Top 10 categories (and vulnerability type keywords) to controls
across SOC 2, HIPAA, PCI-DSS, GDPR, and MITRE ATT&CK.

All data is embedded locally — no external API calls required.
"""
from typing import Dict, List, Any

# ─── Master compliance map keyed by OWASP category ───────────────────────────
OWASP_COMPLIANCE_MAP: Dict[str, Dict[str, List[Dict[str, str]]]] = {

    "A01:2021 - Broken Access Control": {
        "soc2": [
            {
                "control_id": "CC6.1",
                "title": "Logical Access Controls",
                "impact_level": "HIGH",
                "rationale": "Broken access control allows unauthorised users to read, modify, or delete data, violating logical access security commitments.",
                "remediation_note": "Implement role-based access control (RBAC) and validate permissions on every request.",
                "auditor_summary": "Control CC6.1 requires logical access restrictions. Broken access control constitutes a direct violation.",
                "developer_summary": "Add @require_auth decorators / middleware on every endpoint that touches sensitive data. Validate object-level permissions, not just route-level.",
            },
            {
                "control_id": "CC6.3",
                "title": "Role-Based Access Management",
                "impact_level": "HIGH",
                "rationale": "Privilege escalation paths violate the principle of least privilege required by SOC 2.",
                "remediation_note": "Audit and restrict role assignments; implement just-in-time privilege.",
                "auditor_summary": "SOC 2 CC6.3 requires role assignment controls. Privilege escalation findings are direct evidence of deficiency.",
                "developer_summary": "Review role assignment logic; ensure roles cannot be self-escalated via API parameters.",
            },
        ],
        "hipaa": [
            {
                "control_id": "§164.312(a)(1)",
                "title": "Access Control",
                "impact_level": "HIGH",
                "rationale": "HIPAA requires technical policies to allow access only to authorised persons. Broken access control exposes PHI.",
                "remediation_note": "Implement unique user identification and emergency access procedures.",
                "auditor_summary": "This finding represents a potential HIPAA access control violation with PHI exposure risk.",
                "developer_summary": "Ensure ePHI endpoints enforce user-specific access tokens and log every access attempt.",
            },
        ],
        "pci_dss": [
            {
                "control_id": "7.1",
                "title": "Limit access to system components",
                "impact_level": "HIGH",
                "rationale": "PCI DSS requires cardholder data access to be restricted to only those with a legitimate business need.",
                "remediation_note": "Implement access control lists; deny by default.",
                "auditor_summary": "Requirement 7 non-compliance. Cardholder data may be reachable by unauthorised actors.",
                "developer_summary": "Add explicit ACL checks before any payment data read/write operations.",
            },
        ],
        "gdpr": [
            {
                "control_id": "Art. 5(1)(f)",
                "title": "Integrity and Confidentiality",
                "impact_level": "HIGH",
                "rationale": "GDPR requires personal data be processed in a manner ensuring appropriate security, including protection against unauthorised access.",
                "remediation_note": "Apply access controls; document data flows; perform DPIA.",
                "auditor_summary": "Art. 5 integrity principle violated. Supervisory authority may issue corrective measures.",
                "developer_summary": "Ensure personal data endpoints validate user consent scope and enforce field-level access.",
            },
            {
                "control_id": "Art. 32",
                "title": "Security of Processing",
                "impact_level": "HIGH",
                "rationale": "Art. 32 mandates technical measures to ensure data security. Broken access control is direct evidence of inadequate measures.",
                "remediation_note": "Document and implement technical measures; conduct regular testing.",
                "auditor_summary": "Art. 32 requires ongoing security measures. This finding demonstrates a gap.",
                "developer_summary": "Conduct a security review of all data processing endpoints and apply least-privilege access.",
            },
        ],
        "mitre": [
            {
                "control_id": "T1078",
                "title": "Valid Accounts",
                "impact_level": "HIGH",
                "rationale": "Attackers exploit broken access control to use valid account credentials beyond their authorised scope.",
                "remediation_note": "Monitor for privilege abuse; implement behavioural analytics.",
                "auditor_summary": "MITRE T1078 — adversaries may use legitimate credentials to access unauthorised resources.",
                "developer_summary": "Add anomaly detection on access patterns; alert on out-of-scope resource access.",
            },
        ],
    },

    "A02:2021 - Cryptographic Failures": {
        "soc2": [
            {
                "control_id": "CC6.7",
                "title": "Data Transmission Encryption",
                "impact_level": "HIGH",
                "rationale": "SOC 2 requires protection of information during transmission. Weak or missing cryptography violates this requirement.",
                "remediation_note": "Enforce TLS 1.2+ for all transmissions; use AES-256 for data at rest.",
                "auditor_summary": "CC6.7 encryption-in-transit requirement not met. Data is exposed during network communication.",
                "developer_summary": "Replace deprecated ciphers (MD5, SHA1, DES). Enforce HTTPS-only; set HSTS headers.",
            },
        ],
        "hipaa": [
            {
                "control_id": "§164.312(a)(2)(iv)",
                "title": "Encryption and Decryption of ePHI",
                "impact_level": "HIGH",
                "rationale": "HIPAA addressable specification requires encryption of ePHI at rest and in transit.",
                "remediation_note": "Encrypt ePHI with AES-256; use TLS 1.2+ for transmission.",
                "auditor_summary": "ePHI may be exposed due to cryptographic failure. Breach notification rules may apply.",
                "developer_summary": "Audit all PHI storage and transmission paths; apply field-level encryption where needed.",
            },
        ],
        "pci_dss": [
            {
                "control_id": "4.1",
                "title": "Strong cryptography for cardholder data in transit",
                "impact_level": "CRITICAL",
                "rationale": "PCI DSS Req. 4 mandates strong cryptography for transmitting cardholder data over open networks.",
                "remediation_note": "Use TLS 1.2/1.3; disable SSL/TLS 1.0/1.1; rotate keys annually.",
                "auditor_summary": "Requirement 4 violation. Cardholder data may be intercepted in transit.",
                "developer_summary": "Remove all non-TLS endpoints handling payment data. Implement certificate pinning.",
            },
        ],
        "gdpr": [
            {
                "control_id": "Art. 32(1)(a)",
                "title": "Pseudonymisation and Encryption",
                "impact_level": "HIGH",
                "rationale": "GDPR Art. 32 explicitly lists encryption as a technical measure for data security.",
                "remediation_note": "Encrypt personal data; implement pseudonymisation; document the encryption approach.",
                "auditor_summary": "Art. 32 encryption requirement not satisfied. Fine risk up to 2% of global turnover.",
                "developer_summary": "Audit all personal data fields for encryption at rest; use envelope encryption pattern.",
            },
        ],
        "mitre": [
            {
                "control_id": "T1040",
                "title": "Network Sniffing",
                "impact_level": "HIGH",
                "rationale": "Weak cryptography allows network sniffing attacks to capture plaintext credentials or data.",
                "remediation_note": "Enforce strong TLS; monitor for downgrade attacks.",
                "auditor_summary": "MITRE T1040 — weak crypto enables credential capture via network sniffing.",
                "developer_summary": "Enforce TLS 1.3, HSTS, HPKP; disable cipher suites below 128-bit.",
            },
        ],
    },

    "A03:2021 - Injection": {
        "soc2": [
            {
                "control_id": "CC7.1",
                "title": "Vulnerability Detection",
                "impact_level": "CRITICAL",
                "rationale": "SOC 2 CC7.1 requires vulnerability management. Injection vulnerabilities represent unmitigated known attack vectors.",
                "remediation_note": "Use parameterised queries; validate all input; implement WAF.",
                "auditor_summary": "CC7.1 — injection vulnerability found in production code. Vulnerability management process has a gap.",
                "developer_summary": "Replace all string-concatenated queries with parameterised/prepared statements.",
            },
        ],
        "hipaa": [
            {
                "control_id": "§164.312(c)(1)",
                "title": "Integrity Controls",
                "impact_level": "CRITICAL",
                "rationale": "SQL/command injection can corrupt or exfiltrate ePHI, violating HIPAA integrity requirements.",
                "remediation_note": "Use ORM with parameterised queries; conduct SAST scans regularly.",
                "auditor_summary": "HIPAA integrity controls insufficient. ePHI may be modified or exfiltrated via injection.",
                "developer_summary": "Audit all database queries handling PHI. Use SQLAlchemy ORM or prepared statements exclusively.",
            },
        ],
        "pci_dss": [
            {
                "control_id": "6.3.1",
                "title": "Address Common Vulnerabilities",
                "impact_level": "CRITICAL",
                "rationale": "PCI DSS Req. 6.3.1 explicitly lists injection flaws as vulnerabilities to address.",
                "remediation_note": "Parameterise all queries; implement input validation; use WAF in front of payment pages.",
                "auditor_summary": "Req. 6 violation — injection flaw found. Emergency remediation required before next QSA audit.",
                "developer_summary": "All payment-related endpoints must use prepared statements. Block test until fixed.",
            },
        ],
        "gdpr": [
            {
                "control_id": "Art. 32(1)(b)",
                "title": "Ongoing Confidentiality and Integrity",
                "impact_level": "CRITICAL",
                "rationale": "Injection attacks directly compromise data confidentiality and integrity, violating Art. 32.",
                "remediation_note": "Fix injection; report data breach if personal data was accessed via exploitation.",
                "auditor_summary": "Injection finding may constitute a personal data breach. 72-hour notification obligation may apply.",
                "developer_summary": "Treat as P0 bug — fix immediately. Log any suspicious query patterns for breach assessment.",
            },
        ],
        "mitre": [
            {
                "control_id": "T1190",
                "title": "Exploit Public-Facing Application",
                "impact_level": "CRITICAL",
                "rationale": "Injection is one of the primary techniques used to exploit public-facing applications.",
                "remediation_note": "Deploy WAF; conduct regular penetration testing; patch immediately.",
                "auditor_summary": "MITRE T1190 — public-facing application exploitation via injection is a well-documented attack path.",
                "developer_summary": "This is a direct exploitation vector. Prioritise above all other findings.",
            },
        ],
    },

    "A04:2021 - Insecure Design": {
        "soc2": [
            {
                "control_id": "CC8.1",
                "title": "Change Management",
                "impact_level": "MEDIUM",
                "rationale": "Insecure design indicates security was not considered during development, violating change management quality gates.",
                "remediation_note": "Introduce threat modelling in design phase; implement security review gates.",
                "auditor_summary": "CC8.1 change management process lacks security design review. Systemic risk indicator.",
                "developer_summary": "Conduct threat modelling using STRIDE for new features. Add security acceptance criteria.",
            },
        ],
        "gdpr": [
            {
                "control_id": "Art. 25",
                "title": "Data Protection by Design and by Default",
                "impact_level": "HIGH",
                "rationale": "GDPR Art. 25 mandates privacy by design. Insecure design is direct evidence of non-compliance.",
                "remediation_note": "Embed data minimisation, privacy controls, and access restrictions at design stage.",
                "auditor_summary": "Art. 25 data protection by design requirement not implemented. Systemic compliance gap.",
                "developer_summary": "Add privacy impact assessment to design docs. Default to minimum data collection.",
            },
        ],
        "mitre": [
            {
                "control_id": "T1204",
                "title": "User Execution",
                "impact_level": "MEDIUM",
                "rationale": "Insecure design can be exploited via user-triggered execution paths.",
                "remediation_note": "Review user interaction flows for abuse potential; add rate limiting and confirmation steps.",
                "auditor_summary": "MITRE T1204 — insecure design enables attacker-controlled user execution paths.",
                "developer_summary": "Review all user-facing action endpoints for abuse (CSRF, clickjacking, double-submit).",
            },
        ],
    },

    "A05:2021 - Security Misconfiguration": {
        "soc2": [
            {
                "control_id": "CC6.6",
                "title": "Security Configuration Management",
                "impact_level": "HIGH",
                "rationale": "SOC 2 requires secure configuration of all system components. Misconfiguration violates this requirement.",
                "remediation_note": "Harden default configurations; implement CIS benchmarks; scan for misconfigs regularly.",
                "auditor_summary": "CC6.6 — security misconfiguration found. Configuration management process has gaps.",
                "developer_summary": "Disable debug mode in production. Remove default credentials. Apply security headers.",
            },
        ],
        "pci_dss": [
            {
                "control_id": "2.2",
                "title": "Configuration Standards",
                "impact_level": "HIGH",
                "rationale": "PCI DSS Req. 2 requires secure configuration standards for all system components.",
                "remediation_note": "Apply vendor-provided security hardening guidelines; remove unused services.",
                "auditor_summary": "Req. 2 violation. System configuration does not meet secure baseline requirements.",
                "developer_summary": "Review all service configurations against CIS benchmarks. Remove unnecessary services.",
            },
        ],
        "gdpr": [
            {
                "control_id": "Art. 32",
                "title": "Security of Processing",
                "impact_level": "MEDIUM",
                "rationale": "Misconfiguration indicates inadequate technical measures required by Art. 32.",
                "remediation_note": "Implement configuration management; conduct regular security assessments.",
                "auditor_summary": "Art. 32 technical measures inadequate due to misconfiguration.",
                "developer_summary": "Review security headers, CORS settings, and server hardening before production release.",
            },
        ],
        "mitre": [
            {
                "control_id": "T1592",
                "title": "Gather Victim Host Information",
                "impact_level": "MEDIUM",
                "rationale": "Misconfigurations expose system information that attackers use for reconnaissance.",
                "remediation_note": "Disable version headers; remove debug endpoints; suppress stack traces in production.",
                "auditor_summary": "MITRE T1592 — misconfiguration enables attacker reconnaissance of system internals.",
                "developer_summary": "Set DEBUG=false; remove /debug and /info endpoints; configure error pages to hide stack traces.",
            },
        ],
    },

    "A06:2021 - Vulnerable and Outdated Components": {
        "soc2": [
            {
                "control_id": "CC7.1",
                "title": "Vulnerability and Threat Intelligence",
                "impact_level": "HIGH",
                "rationale": "SOC 2 requires monitoring for vulnerabilities. Using outdated components with known CVEs is a direct deficiency.",
                "remediation_note": "Implement dependency scanning in CI/CD; update dependencies regularly; subscribe to CVE feeds.",
                "auditor_summary": "CC7.1 — known CVE in a third-party dependency. Vulnerability management process insufficient.",
                "developer_summary": "Run `npm audit` / `pip audit` in CI. Set up Dependabot. Upgrade the flagged dependency immediately.",
            },
        ],
        "hipaa": [
            {
                "control_id": "§164.308(a)(1)",
                "title": "Risk Analysis",
                "impact_level": "HIGH",
                "rationale": "HIPAA requires regular risk analysis. Known CVEs in components handling ePHI represent unmitigated risk.",
                "remediation_note": "Include dependency CVE scanning in annual HIPAA risk analysis.",
                "auditor_summary": "Risk analysis incomplete — known CVEs not remediated. HIPAA Security Rule gap.",
                "developer_summary": "Prioritise updating dependencies that process or store PHI. Document risk acceptance for deferred updates.",
            },
        ],
        "pci_dss": [
            {
                "control_id": "6.2",
                "title": "Protect Components from Known Vulnerabilities",
                "impact_level": "HIGH",
                "rationale": "PCI DSS Req. 6.2 requires all system components to be protected from known vulnerabilities.",
                "remediation_note": "Patch within 1 month for critical CVEs; integrate automated scanning.",
                "auditor_summary": "Req. 6.2 violation — known vulnerability in component processing card data.",
                "developer_summary": "Upgrade flagged package. If upgrade breaks compatibility, document compensating control.",
            },
        ],
        "gdpr": [
            {
                "control_id": "Art. 32(1)(d)",
                "title": "Regular Testing and Evaluation",
                "impact_level": "MEDIUM",
                "rationale": "Art. 32(1)(d) requires regular testing of security measures. Outdated dependencies indicate this is not occurring.",
                "remediation_note": "Implement automated dependency scanning; establish patch SLAs.",
                "auditor_summary": "Art. 32(1)(d) — security testing process does not cover third-party dependencies.",
                "developer_summary": "Add `safety check` or `pip-audit` to your CI pipeline. Set up automated PR alerts for CVEs.",
            },
        ],
        "mitre": [
            {
                "control_id": "T1195",
                "title": "Supply Chain Compromise",
                "impact_level": "HIGH",
                "rationale": "Vulnerable third-party components are a common supply chain attack vector.",
                "remediation_note": "Use dependency pinning; verify checksums; monitor for typosquatting.",
                "auditor_summary": "MITRE T1195 — supply chain risk from vulnerable dependency.",
                "developer_summary": "Pin exact dependency versions; verify package integrity hashes in requirements.",
            },
        ],
    },

    "A07:2021 - Identification and Authentication Failures": {
        "soc2": [
            {
                "control_id": "CC6.2",
                "title": "Authentication Management",
                "impact_level": "HIGH",
                "rationale": "SOC 2 CC6.2 requires strong authentication. Weak or broken auth is a direct violation.",
                "remediation_note": "Implement MFA; enforce strong password policies; use secure session management.",
                "auditor_summary": "CC6.2 — authentication controls inadequate. Unauthorised access risk is elevated.",
                "developer_summary": "Add MFA to privileged accounts. Enforce bcrypt/argon2 for password hashing. Implement session expiry.",
            },
        ],
        "hipaa": [
            {
                "control_id": "§164.312(d)",
                "title": "Person or Entity Authentication",
                "impact_level": "HIGH",
                "rationale": "HIPAA requires verifying that a person seeking access to ePHI is who they claim to be.",
                "remediation_note": "Implement MFA for all ePHI access; enforce unique user IDs.",
                "auditor_summary": "HIPAA entity authentication requirement not met. ePHI access may be unauthorised.",
                "developer_summary": "Require MFA for all users accessing ePHI. Log all authentication events.",
            },
        ],
        "pci_dss": [
            {
                "control_id": "8.3",
                "title": "Strong Authentication for All Users",
                "impact_level": "HIGH",
                "rationale": "PCI DSS Req. 8.3 requires MFA for all non-console admin access and remote user access.",
                "remediation_note": "Implement MFA; disable shared credentials; enforce session timeouts.",
                "auditor_summary": "Req. 8.3 MFA requirement violated. Administrative access to CDE without MFA.",
                "developer_summary": "Add TOTP/FIDO2 MFA to admin dashboard. Log failed authentication attempts.",
            },
        ],
        "gdpr": [
            {
                "control_id": "Art. 32",
                "title": "Ability to Ensure Ongoing Confidentiality",
                "impact_level": "HIGH",
                "rationale": "Weak authentication undermines the confidentiality of personal data required by Art. 32.",
                "remediation_note": "Implement strong authentication; document technical measures.",
                "auditor_summary": "Authentication failure risk creates personal data exposure. Art. 32 compliance gap.",
                "developer_summary": "Audit all authentication flows. Add rate limiting to login endpoints. Use secure cookies.",
            },
        ],
        "mitre": [
            {
                "control_id": "T1110",
                "title": "Brute Force",
                "impact_level": "HIGH",
                "rationale": "Authentication failures enable brute force and credential stuffing attacks.",
                "remediation_note": "Implement account lockout; add CAPTCHA; monitor login anomalies.",
                "auditor_summary": "MITRE T1110 — weak authentication enables brute force credential attacks.",
                "developer_summary": "Add exponential backoff after failed logins. Integrate account lockout after 5 attempts.",
            },
        ],
    },

    "A08:2021 - Software and Data Integrity Failures": {
        "soc2": [
            {
                "control_id": "CC8.1",
                "title": "Software Development Lifecycle",
                "impact_level": "HIGH",
                "rationale": "SOC 2 requires secure SDLC practices. Integrity failures indicate code or data can be tampered with.",
                "remediation_note": "Implement code signing; verify integrity of CI/CD pipeline artifacts.",
                "auditor_summary": "CC8.1 — SDLC integrity controls missing. Software supply chain may be compromised.",
                "developer_summary": "Sign container images. Verify checksums of downloaded artifacts in CI/CD.",
            },
        ],
        "gdpr": [
            {
                "control_id": "Art. 5(1)(f)",
                "title": "Integrity and Confidentiality",
                "impact_level": "HIGH",
                "rationale": "Data integrity failures directly violate GDPR's requirement for data integrity.",
                "remediation_note": "Implement integrity checks; use cryptographic hashes; validate data on input and output.",
                "auditor_summary": "GDPR integrity principle at risk. Personal data may be tampered with.",
                "developer_summary": "Add HMAC signatures to sensitive data objects. Validate on every read.",
            },
        ],
        "mitre": [
            {
                "control_id": "T1553",
                "title": "Subvert Trust Controls",
                "impact_level": "HIGH",
                "rationale": "Software integrity failures allow attackers to subvert trust verification mechanisms.",
                "remediation_note": "Implement code signing; use SRI for web assets; enforce package integrity checks.",
                "auditor_summary": "MITRE T1553 — integrity failure enables trust subversion.",
                "developer_summary": "Add Subresource Integrity (SRI) to CDN scripts. Use signed commits.",
            },
        ],
    },

    "A09:2021 - Security Logging and Monitoring Failures": {
        "soc2": [
            {
                "control_id": "CC7.2",
                "title": "Security Incident Monitoring",
                "impact_level": "MEDIUM",
                "rationale": "SOC 2 CC7.2 requires monitoring of system activity for security events. Logging failures directly violate this.",
                "remediation_note": "Implement centralised logging; set up SIEM; alert on suspicious activity.",
                "auditor_summary": "CC7.2 — insufficient logging means security incidents may go undetected.",
                "developer_summary": "Add structured logging (JSON) to all auth, data access, and admin actions. Ship to SIEM.",
            },
        ],
        "hipaa": [
            {
                "control_id": "§164.312(b)",
                "title": "Audit Controls",
                "impact_level": "HIGH",
                "rationale": "HIPAA requires hardware, software, and procedural mechanisms to record and examine activity in systems containing ePHI.",
                "remediation_note": "Implement comprehensive audit logging for all ePHI access; retain logs for 6+ years.",
                "auditor_summary": "HIPAA audit control requirement not met. ePHI access cannot be reconstructed.",
                "developer_summary": "Log every ePHI read/write with user ID, timestamp, and IP. Store in tamper-evident log store.",
            },
        ],
        "pci_dss": [
            {
                "control_id": "10.1",
                "title": "Implement Audit Logs for All System Access",
                "impact_level": "HIGH",
                "rationale": "PCI DSS Req. 10 requires audit logs for all access to system components, especially CDE.",
                "remediation_note": "Log all user access to cardholder data; retain for 12 months; alert on anomalies.",
                "auditor_summary": "Req. 10 logging requirement not satisfied. Forensic reconstruction of incidents not possible.",
                "developer_summary": "Implement structured audit logs for payment data access. Include correlation IDs.",
            },
        ],
        "mitre": [
            {
                "control_id": "T1562",
                "title": "Impair Defenses",
                "impact_level": "MEDIUM",
                "rationale": "Logging failures allow attackers to operate without detection, impairing defensive capabilities.",
                "remediation_note": "Centralise logs; monitor log integrity; alert on log deletion or gaps.",
                "auditor_summary": "MITRE T1562 — insufficient logging enables attackers to operate undetected.",
                "developer_summary": "Ship logs to external SIEM so attackers cannot delete them from the compromised host.",
            },
        ],
    },

    "A10:2021 - Server-Side Request Forgery": {
        "soc2": [
            {
                "control_id": "CC6.6",
                "title": "Network Access Controls",
                "impact_level": "HIGH",
                "rationale": "SSRF allows attackers to pivot from the application server to internal services, bypassing network controls.",
                "remediation_note": "Validate and allowlist outbound URL targets; segment internal network.",
                "auditor_summary": "CC6.6 — SSRF enables network boundary bypass. Internal services may be exposed.",
                "developer_summary": "Implement URL allowlisting for any server-side HTTP fetch. Block private IP ranges.",
            },
        ],
        "pci_dss": [
            {
                "control_id": "1.3",
                "title": "Prohibit Direct Internet Access to/from CDE",
                "impact_level": "CRITICAL",
                "rationale": "SSRF can bypass network segmentation and allow direct access to the cardholder data environment.",
                "remediation_note": "Implement URL allowlisting; use egress firewalls; monitor outbound requests.",
                "auditor_summary": "Req. 1.3 network segmentation violation risk via SSRF. CDE may be reachable.",
                "developer_summary": "Block all outbound requests to RFC1918 addresses from application tier. Log all external fetch calls.",
            },
        ],
        "mitre": [
            {
                "control_id": "T1090",
                "title": "Proxy",
                "impact_level": "HIGH",
                "rationale": "SSRF can be used to proxy requests through the server to reach internal targets.",
                "remediation_note": "Validate URL schemes; block internal IP ranges; use URL parsing libraries.",
                "auditor_summary": "MITRE T1090 — SSRF enables proxy attacks to internal infrastructure.",
                "developer_summary": "Use a dedicated HTTP client with URL validation. Reject file://, gopher://, and internal IP targets.",
            },
        ],
    },
}

# ─── Keyword → OWASP category fallback ───────────────────────────────────────
KEYWORD_TO_OWASP: Dict[str, str] = {
    "sql": "A03:2021 - Injection",
    "injection": "A03:2021 - Injection",
    "xss": "A03:2021 - Injection",
    "command": "A03:2021 - Injection",
    "ldap": "A03:2021 - Injection",
    "template": "A03:2021 - Injection",
    "access control": "A01:2021 - Broken Access Control",
    "idor": "A01:2021 - Broken Access Control",
    "privilege": "A01:2021 - Broken Access Control",
    "path traversal": "A01:2021 - Broken Access Control",
    "directory traversal": "A01:2021 - Broken Access Control",
    "csrf": "A01:2021 - Broken Access Control",
    "crypto": "A02:2021 - Cryptographic Failures",
    "encrypt": "A02:2021 - Cryptographic Failures",
    "hash": "A02:2021 - Cryptographic Failures",
    "md5": "A02:2021 - Cryptographic Failures",
    "sha1": "A02:2021 - Cryptographic Failures",
    "weak cipher": "A02:2021 - Cryptographic Failures",
    "hardcoded": "A02:2021 - Cryptographic Failures",
    "secret": "A02:2021 - Cryptographic Failures",
    "password": "A07:2021 - Identification and Authentication Failures",
    "auth": "A07:2021 - Identification and Authentication Failures",
    "session": "A07:2021 - Identification and Authentication Failures",
    "jwt": "A07:2021 - Identification and Authentication Failures",
    "token": "A07:2021 - Identification and Authentication Failures",
    "misconfigur": "A05:2021 - Security Misconfiguration",
    "default config": "A05:2021 - Security Misconfiguration",
    "debug": "A05:2021 - Security Misconfiguration",
    "cve": "A06:2021 - Vulnerable and Outdated Components",
    "outdated": "A06:2021 - Vulnerable and Outdated Components",
    "vulnerable": "A06:2021 - Vulnerable and Outdated Components",
    "dependency": "A06:2021 - Vulnerable and Outdated Components",
    "ssrf": "A10:2021 - Server-Side Request Forgery",
    "request forgery": "A10:2021 - Server-Side Request Forgery",
    "logging": "A09:2021 - Security Logging and Monitoring Failures",
    "audit log": "A09:2021 - Security Logging and Monitoring Failures",
    "deserialization": "A08:2021 - Software and Data Integrity Failures",
    "integrity": "A08:2021 - Software and Data Integrity Failures",
    "supply chain": "A08:2021 - Software and Data Integrity Failures",
    "insecure design": "A04:2021 - Insecure Design",
}

ALL_FRAMEWORKS = ["soc2", "hipaa", "pci_dss", "gdpr", "mitre"]


def resolve_owasp_category(vuln: Dict[str, Any]) -> str:
    """
    Return the best OWASP category for a vulnerability dict.
    Tries: owasp_category field → title/description keyword match → default.
    """
    cat = vuln.get("owasp_category", "").strip()
    if cat and cat in OWASP_COMPLIANCE_MAP:
        return cat

    # keyword fallback
    text = (
        (vuln.get("title", "") + " " + vuln.get("description", "") + " " + vuln.get("owasp_category", ""))
        .lower()
    )
    for kw, category in KEYWORD_TO_OWASP.items():
        if kw in text:
            return category

    return "A05:2021 - Security Misconfiguration"


def get_compliance_mappings(vuln: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Return a flat list of compliance mapping dicts for a single vulnerability.
    Each entry has: framework, control_id, title, impact_level,
                    rationale, remediation_note, auditor_summary, developer_summary.
    """
    owasp_cat = resolve_owasp_category(vuln)
    framework_map = OWASP_COMPLIANCE_MAP.get(owasp_cat, {})

    results: List[Dict[str, str]] = []
    for framework, controls in framework_map.items():
        for ctrl in controls:
            results.append({
                "vuln_id":           vuln.get("id", ""),
                "framework":         framework.upper().replace("_", "-"),
                "control_id":        ctrl["control_id"],
                "title":             ctrl["title"],
                "impact_level":      ctrl["impact_level"],
                "rationale":         ctrl["rationale"],
                "remediation_note":  ctrl["remediation_note"],
                "auditor_summary":   ctrl["auditor_summary"],
                "developer_summary": ctrl["developer_summary"],
            })
    return results


def get_compliance_blast_radius(all_mappings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Summarise compliance impact across all vulnerabilities.
    Returns counts per framework and top impacted controls.
    """
    framework_counts: Dict[str, int] = {}
    high_risk_controls: List[Dict[str, str]] = []
    touched_controls: Dict[str, set] = {}

    for m in all_mappings:
        fw = m.get("framework", "UNKNOWN")
        framework_counts[fw] = framework_counts.get(fw, 0) + 1
        if m.get("impact_level") in ("HIGH", "CRITICAL"):
            high_risk_controls.append({
                "framework":  fw,
                "control_id": m.get("control_id", ""),
                "title":      m.get("title", ""),
            })
        if fw not in touched_controls:
            touched_controls[fw] = set()
        touched_controls[fw].add(m.get("control_id", ""))

    unique_controls_per_fw = {fw: len(ids) for fw, ids in touched_controls.items()}

    return {
        "framework_counts":       framework_counts,
        "high_risk_count":        len(high_risk_controls),
        "top_high_risk_controls": high_risk_controls[:5],
        "unique_controls_per_fw": unique_controls_per_fw,
        "frameworks_touched":     list(framework_counts.keys()),
    }
