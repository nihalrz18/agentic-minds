"""
Secrets Agent — Phase 2 (parallel).
Walks all repo files and detects hardcoded secrets via regex patterns.
LLM validates findings to filter out test/example data.
"""
import os
import re
import uuid
import json
import autogen
from pathlib import Path
from typing import Dict, Any, List

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", "target", "vendor",
}

BINARY_EXTS = {
    ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".otf", ".pdf", ".zip", ".gz", ".tar", ".bin",
    ".exe", ".dll", ".so", ".pyc", ".pyo", ".class", ".jar", ".mp3",
    ".mp4", ".avi", ".mov", ".lock",
}

# (regex_pattern, title, severity, cvss_score, cvss_vector)
SECRET_PATTERNS: List[tuple] = [
    (r'(?i)\bpassword\s*[=:]\s*["\'][^"\']{6,}["\']',
     "Hardcoded Password", "HIGH", 8.0,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    (r'(?i)\bpasswd\s*[=:]\s*["\'][^"\']{6,}["\']',
     "Hardcoded Password (passwd)", "HIGH", 8.0,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    (r'(?i)(api[_\-]?key)\s*[=:]\s*["\'][^"\']{8,}["\']',
     "Hardcoded API Key", "HIGH", 7.5,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    (r'AKIA[0-9A-Z]{16}',
     "AWS Access Key ID", "CRITICAL", 10.0,
     "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    (r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*["\'][^"\']{20,}["\']',
     "AWS Secret Access Key", "CRITICAL", 10.0,
     "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    (r'ghp_[a-zA-Z0-9]{36}',
     "GitHub Personal Access Token", "CRITICAL", 9.3,
     "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"),
    (r'ghs_[a-zA-Z0-9]{36}',
     "GitHub Server Token", "CRITICAL", 9.3,
     "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"),
    (r'eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}',
     "JWT Token Exposed", "HIGH", 8.1,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    (r'sk_live_[a-zA-Z0-9]{24,}',
     "Stripe Live Secret Key", "CRITICAL", 9.1,
     "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"),
    (r'SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{22,}',
     "SendGrid API Key", "CRITICAL", 9.1,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    (r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
     "Private Key in Repository", "CRITICAL", 10.0,
     "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    (r'xox[baprs]-[0-9A-Za-z]{10,}',
     "Slack Token", "HIGH", 7.5,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    (r'(?i)(database_url|db_url|db_connection)\s*[=:]\s*["\'][a-z]{2,8}://[^@"\']+@[^"\']+["\']',
     "Database Connection String with Credentials", "HIGH", 8.1,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    (r'(?i)(twilio_auth|twilio_token)\s*[=:]\s*["\'][a-zA-Z0-9]{32}["\']',
     "Twilio Auth Token", "HIGH", 7.5,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    (r'(?i)(private[_\-]?key)\s*[=:]\s*["\'][^"\']{20,}["\']',
     "Hardcoded Private Key Material", "HIGH", 8.0,
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
]

# Lines that are likely just examples/placeholders
PLACEHOLDER_PATTERNS = [
    r"your[_\-]?key[_\-]?here", r"your[_\-]?secret",
    r"example", r"placeholder", r"changeme", r"<your", r"\$\{",
    r"xxx+", r"test_?key", r"dummy", r"replace_me",
]


def _is_likely_placeholder(value: str) -> bool:
    val_lower = value.lower()
    return any(re.search(p, val_lower) for p in PLACEHOLDER_PATTERNS)


def _mask(s: str) -> str:
    if len(s) <= 8:
        return "****"
    vis = max(3, len(s) // 6)
    return s[:vis] + "****" + s[-vis:]


class SecretsAgent:
    def __init__(self, llm_config: dict):
        self.llm_config = llm_config

    def run(self, scan_result: dict) -> Dict[str, Any]:
        clone_path = scan_result.get("clone_path", "")
        if not clone_path or not os.path.exists(clone_path):
            return {"vulnerabilities": [], "error": "Clone path not found"}

        raw_findings = self._scan_files(clone_path)
        validated    = self._llm_validate(raw_findings)
        return {"vulnerabilities": validated}

    # ──────────────────────────────────────────────────────────────────────────
    def _scan_files(self, clone_path: str) -> List[Dict[str, Any]]:
        findings = []
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
                seen_in_file: set = set()
                for pattern, title, severity, cvss, vector in SECRET_PATTERNS:
                    for i, line in enumerate(lines):
                        m = re.search(pattern, line)
                        if not m:
                            continue
                        if (fname, title) in seen_in_file:
                            continue
                        matched_val = m.group(0)
                        if _is_likely_placeholder(matched_val):
                            continue
                        seen_in_file.add((fname, title))
                        masked_line = _mask(matched_val)
                        findings.append({
                            "id":             f"SCRT-{uuid.uuid4().hex[:8]}",
                            "title":          f"{title} — {fname}",
                            "description":    (
                                f"{title} detected at line {i+1}. "
                                "Exposed credentials may allow unauthorised access to external systems."
                            ),
                            "file_path":      rel_path,
                            "line_number":    i + 1,
                            "severity":       severity,
                            "severity_raw":   "ERROR" if severity == "CRITICAL" else "WARNING",
                            "cvss_score":     cvss,
                            "cvss_vector":    vector,
                            "owasp_category": "A02:2021 - Cryptographic Failures",
                            "raw_message":    masked_line,
                            "code_snippet":   masked_line,
                            "layer":          "secret",
                            "references": [
                                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                            ],
                            "_raw_line":      line.strip()[:300],  # for LLM validation only
                        })
                        break
        return findings

    def _llm_validate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Ask LLM to filter out obvious false positives (test data, placeholders)."""
        if not findings:
            return []

        # Only validate up to 10 findings to stay within token limits
        to_validate = findings[:10]
        rest        = findings[10:]

        summary = json.dumps([
            {
                "id":       f["id"],
                "title":    f["title"],
                "raw_line": f.get("_raw_line", "")[:150],
            }
            for f in to_validate
        ], indent=2)

        try:
            agent = autogen.AssistantAgent(
                name="SecretsValidator",
                llm_config=self.llm_config,
                system_message=(
                    "You are a security engineer specialising in secret detection. "
                    "Given a list of potential secret findings, classify each as "
                    "'real' (genuine credential) or 'false_positive' (test data, "
                    "example, placeholder). Output a JSON array with {id, verdict} only."
                ),
            )
            proxy = autogen.UserProxyAgent(
                name="user_proxy",
                human_input_mode="NEVER",
                max_consecutive_auto_reply=1,
                code_execution_config=False,
            )
            prompt = (
                f"Classify each finding as 'real' or 'false_positive':\n{summary}\n"
                "Output JSON array: [{\"id\": \"SCRT-xxx\", \"verdict\": \"real\"}]"
            )
            proxy.initiate_chat(agent, message=prompt, max_turns=1)
            resp = (agent.last_message(proxy) or {}).get("content", "[]")
            start = resp.find("[")
            end   = resp.rfind("]") + 1
            if start >= 0:
                verdicts = json.loads(resp[start:end])
                fp_ids = {v["id"] for v in verdicts if v.get("verdict") == "false_positive"}
                to_validate = [f for f in to_validate if f["id"] not in fp_ids]
        except Exception:
            pass  # LLM unavailable — keep all findings

        # Strip internal _raw_line field before returning
        validated = []
        for f in (to_validate + rest):
            f.pop("_raw_line", None)
            validated.append(f)
        return validated
