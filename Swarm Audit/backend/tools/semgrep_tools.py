"""
Semgrep wrapper utilities for SwarmAudit.
Maps Semgrep rule IDs to OWASP Top 10 categories and severity labels.
"""
import json
import subprocess
from typing import List, Dict, Any

OWASP_MAPPING: Dict[str, str] = {
    "sql-injection":         "A03:2021 - Injection",
    "sqli":                  "A03:2021 - Injection",
    "xss":                   "A03:2021 - Injection",
    "injection":             "A03:2021 - Injection",
    "command-injection":     "A03:2021 - Injection",
    "code-injection":        "A03:2021 - Injection",
    "ldap-injection":        "A03:2021 - Injection",
    "xpath-injection":       "A03:2021 - Injection",
    "secret":                "A02:2021 - Cryptographic Failures",
    "hardcoded":             "A02:2021 - Cryptographic Failures",
    "crypto":                "A02:2021 - Cryptographic Failures",
    "weak-crypto":           "A02:2021 - Cryptographic Failures",
    "auth":                  "A07:2021 - Identification and Authentication Failures",
    "jwt":                   "A07:2021 - Identification and Authentication Failures",
    "session":               "A07:2021 - Identification and Authentication Failures",
    "csrf":                  "A01:2021 - Broken Access Control",
    "path-traversal":        "A01:2021 - Broken Access Control",
    "broken-access":         "A01:2021 - Broken Access Control",
    "idor":                  "A01:2021 - Broken Access Control",
    "ssrf":                  "A10:2021 - Server-Side Request Forgery",
    "deserialization":       "A08:2021 - Software and Data Integrity Failures",
    "prototype-pollution":   "A08:2021 - Software and Data Integrity Failures",
    "xxe":                   "A05:2021 - Security Misconfiguration",
    "misconfiguration":      "A05:2021 - Security Misconfiguration",
    "open-redirect":         "A01:2021 - Broken Access Control",
    "log-injection":         "A09:2021 - Security Logging and Monitoring Failures",
    "insecure-randomness":   "A02:2021 - Cryptographic Failures",
    "taint":                 "A03:2021 - Injection",
}


def map_owasp(rule_id: str) -> str:
    """Return the OWASP Top 10 category for a Semgrep rule ID."""
    rule_lower = rule_id.lower()
    for key, category in OWASP_MAPPING.items():
        if key in rule_lower:
            return category
    return "A05:2021 - Security Misconfiguration"


def map_severity(severity_raw: str) -> str:
    """Convert Semgrep severity_raw to SwarmAudit severity string."""
    return {
        "ERROR":   "HIGH",
        "WARNING": "MEDIUM",
        "INFO":    "LOW",
        "error":   "HIGH",
        "warning": "MEDIUM",
        "info":    "LOW",
    }.get(severity_raw, "MEDIUM")


def estimate_cvss(severity_raw: str) -> float:
    """Estimate a baseline CVSS score from Semgrep severity."""
    return {"ERROR": 7.5, "WARNING": 5.0, "INFO": 2.0}.get(severity_raw, 5.0)


def run_semgrep(clone_path: str, timeout: int = 120) -> List[Dict[str, Any]]:
    """
    Execute Semgrep against clone_path with OWASP ruleset.
    Returns raw list of finding dicts from Semgrep JSON output.
    """
    try:
        result = subprocess.run(
            [
                "semgrep",
                "--config=p/owasp-top-ten",
                "--json",
                "--quiet",
                "--jobs=1",
                "--timeout=30",
                "--max-memory=150",
                clone_path,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=clone_path,
        )
        if not result.stdout.strip():
            return []
        data = json.loads(result.stdout)
        return data.get("results", [])
    except subprocess.TimeoutExpired:
        return []
    except (json.JSONDecodeError, subprocess.SubprocessError, FileNotFoundError):
        return []
