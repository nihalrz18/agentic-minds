"""
SAST Agent — Phase 2 (parallel).
Runs Semgrep OWASP Top-10 rules plus hardcoded-secrets regex patterns.
"""
import os
import re
import uuid
from pathlib import Path
from typing import Dict, Any, List

from tools.semgrep_tools import run_semgrep, map_owasp, map_severity, estimate_cvss

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", "target",
}

BINARY_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".otf", ".pdf", ".zip", ".gz", ".tar", ".bin",
    ".exe", ".dll", ".so", ".pyc", ".pyo", ".class", ".jar",
}

SECRET_PATTERNS: List[tuple] = [
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']',
     "Hardcoded Password", "HIGH", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.5),
    (r'(?i)(api_key|apikey|api-key)\s*[=:]\s*["\'][^"\']{8,}["\']',
     "Hardcoded API Key", "HIGH", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    (r'AKIA[0-9A-Z]{16}',
     "AWS Access Key ID", "CRITICAL", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    (r'(?i)aws_secret_access_key\s*[=:]\s*["\'][^"\']{20,}["\']',
     "AWS Secret Access Key", "CRITICAL", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    (r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
     "JWT Token Exposed", "HIGH", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 8.1),
    (r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\'][^"\']{8,}["\']',
     "Hardcoded Secret Key", "HIGH", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.5),
    (r'ghp_[a-zA-Z0-9]{36}',
     "GitHub Personal Access Token", "CRITICAL", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", 9.1),
    (r'ghs_[a-zA-Z0-9]{36}',
     "GitHub Server-to-Server Token", "CRITICAL", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", 9.1),
    (r'sk_live_[a-zA-Z0-9]{24,}',
     "Stripe Live Secret Key", "CRITICAL", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", 9.1),
    (r'SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{22,}',
     "SendGrid API Key", "CRITICAL", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
    (r'-----BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY-----',
     "Private Key Exposed", "CRITICAL", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    (r'(?i)(database_url|db_url)\s*[=:]\s*["\'][a-z]{2,10}://[^@"\']+@[^"\']+["\']',
     "Database Connection String", "HIGH", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 8.1),
    (r'xox[baprs]-[0-9]{10,}-[0-9a-zA-Z\-]+',
     "Slack Token", "HIGH", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
]


class SASTAgent:
    def __init__(self, llm_config: dict):
        self.llm_config = llm_config

    def run(self, scan_result: dict) -> Dict[str, Any]:
        clone_path = scan_result.get("clone_path", "")
        if not clone_path or not os.path.exists(clone_path):
            return {"vulnerabilities": [], "total_found": 0, "error": "Clone path not found"}

        vulns: List[Dict[str, Any]] = []
        vulns.extend(self._run_semgrep(clone_path))
        vulns.extend(self._run_regex(clone_path))

        return {"vulnerabilities": vulns, "total_found": len(vulns)}

    # ──────────────────────────────────────────────────────────────────────────
    def _run_semgrep(self, clone_path: str) -> List[Dict[str, Any]]:
        results = []
        findings = run_semgrep(clone_path, timeout=120)
        for f in findings:
            sev_raw  = f.get("extra", {}).get("severity", "WARNING")
            rule_id  = f.get("check_id", "")
            msg      = f.get("extra", {}).get("message", rule_id)[:200]
            results.append({
                "id":             f"SAST-{uuid.uuid4().hex[:8]}",
                "title":          msg[:100],
                "description":    f.get("extra", {}).get("metadata", {}).get(
                                      "message", msg),
                "file_path":      os.path.relpath(f.get("path", ""), clone_path),
                "line_number":    f.get("start", {}).get("line"),
                "severity":       map_severity(sev_raw),
                "severity_raw":   sev_raw,
                "cvss_score":     estimate_cvss(sev_raw),
                "cvss_vector":    "",
                "owasp_category": map_owasp(rule_id),
                "raw_message":    msg,
                "code_snippet":   f.get("extra", {}).get("lines", "")[:500],
                "layer":          "code",
                "references":     f.get("extra", {}).get("metadata", {}).get(
                                      "references", []),
            })
        return results

    def _run_regex(self, clone_path: str) -> List[Dict[str, Any]]:
        results = []
        for root, dirs, files in os.walk(clone_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                if Path(fname).suffix.lower() in BINARY_EXTS:
                    continue
                fpath    = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, clone_path)
                try:
                    content = open(fpath, encoding="utf-8", errors="ignore").read()
                    lines   = content.splitlines()
                except OSError:
                    continue

                seen = set()
                for pattern, title, severity, vector, cvss in SECRET_PATTERNS:
                    for i, line in enumerate(lines):
                        if re.search(pattern, line) and (fname, title) not in seen:
                            seen.add((fname, title))
                            masked = re.sub(
                                r'(["\'])([^"\']{4})[^"\']*([^"\']{4})(["\'])',
                                r'\1\2****\3\4',
                                line,
                            )
                            results.append({
                                "id":             f"SEC-{uuid.uuid4().hex[:8]}",
                                "title":          f"{title} in {fname}",
                                "description":    (
                                    f"Potential {title.lower()} detected. "
                                    "Hardcoded credentials are a critical security risk."
                                ),
                                "file_path":      rel_path,
                                "line_number":    i + 1,
                                "severity":       severity,
                                "severity_raw":   "ERROR" if severity == "CRITICAL" else "WARNING",
                                "cvss_score":     cvss,
                                "cvss_vector":    vector,
                                "owasp_category": "A02:2021 - Cryptographic Failures",
                                "raw_message":    masked.strip()[:200],
                                "code_snippet":   masked.strip()[:200],
                                "layer":          "code",
                                "references": [
                                    "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                                ],
                            })
                            break
        return results
