"""
Validation Agent — runs top findings through an ephemeral Docker sandbox
and produces VERIFIED / UNVERIFIED / INCONCLUSIVE / SKIPPED verdicts.

Consumes PoC output from the PoC Agent and structured vulnerability data.
Persists evidence to Neon DB and streams events via WebSocket.
"""
import asyncio
import logging
import os
import time
from typing import Any, Dict, List

from tools.sandbox_runner import (
    DOCKER_AVAILABLE,
    run_dependency_check,
    run_python_snippet,
    run_static_check,
)

logger = logging.getLogger("validation_agent")

MAX_FINDINGS    = int(os.getenv("VALIDATION_MAX_FINDINGS", "5"))
VALIDATION_ON   = os.getenv("VALIDATION_ENABLED", "true").lower() == "true"

# Patterns that confirm a secret / hardcoded credential finding
_SECRET_PATTERNS = [
    r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]",
    r"(?i)(api_key|apikey|api-key)\s*=\s*['\"][^'\"]{8,}['\"]",
    r"(?i)(secret|token)\s*=\s*['\"][^'\"]{8,}['\"]",
    r"(?i)(aws_access_key_id)\s*=\s*AKI[A-Z0-9]{16}",
    r"(?i)(private_key|-----BEGIN\s+[A-Z]+\s+PRIVATE\s+KEY)",
]


class ValidationAgent:
    """Validates top vulnerabilities in a safe sandbox environment."""

    def __init__(self, llm_config: Dict[str, Any]):
        self.llm_config = llm_config

    def run(
        self,
        all_findings: Dict[str, Any],
        poc_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Synchronous entry point (called via asyncio.to_thread).

        Returns:
            {
                validation_results: List[ValidationEvidence dicts],
                validated_count: int,
                verified_count: int,
                docker_available: bool,
            }
        """
        if not VALIDATION_ON:
            return {
                "validation_results": [],
                "validated_count":    0,
                "verified_count":     0,
                "docker_available":   DOCKER_AVAILABLE,
                "note":               "Validation disabled via VALIDATION_ENABLED env var.",
            }

        vulns   = all_findings.get("vulnerabilities", [])
        exploits: List[Dict[str, Any]] = poc_result.get("exploits", [])

        # Map exploit code by vuln_id for quick lookup
        exploit_map: Dict[str, str] = {}
        for e in exploits:
            vid = e.get("vuln_id") or e.get("id", "")
            if vid:
                exploit_map[vid] = e.get("code", "") or e.get("exploit_code", "")

        # Sort by severity — validate the most critical first
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        top_vulns = sorted(
            vulns,
            key=lambda v: sev_order.get(v.get("severity", "INFO"), 4)
        )[:MAX_FINDINGS]

        results: List[Dict[str, Any]] = []
        verified = 0

        for vuln in top_vulns:
            vid    = vuln.get("id", "")
            layer  = vuln.get("layer", "code")
            title  = vuln.get("title", "")
            t0     = time.time()

            try:
                ev = self._validate_single(vuln, exploit_map.get(vid, ""), layer, title)
            except Exception as exc:
                ev = {
                    "verdict":        "INCONCLUSIVE",
                    "method":         "error",
                    "container_image": "",
                    "command_executed": "",
                    "exit_code":       None,
                    "stdout_excerpt":  "",
                    "stderr_excerpt":  "",
                    "timeout_hit":     False,
                    "duration_ms":     int((time.time() - t0) * 1000),
                    "notes":           f"Validation error: {str(exc)[:200]}",
                }

            ev["vuln_id"] = vid
            results.append(ev)
            if ev.get("verdict") == "VERIFIED":
                verified += 1

        return {
            "validation_results": results,
            "validated_count":    len(results),
            "verified_count":     verified,
            "docker_available":   DOCKER_AVAILABLE,
        }

    def _validate_single(
        self,
        vuln: Dict[str, Any],
        poc_code: str,
        layer: str,
        title: str,
    ) -> Dict[str, Any]:
        """Choose and execute the right validation profile for a single finding."""
        owasp    = vuln.get("owasp_category", "").lower()
        severity = vuln.get("severity", "MEDIUM")
        snippet  = vuln.get("code_snippet", "") or ""

        # ── Profile: Secret / hardcoded credential ────────────────────────────
        if layer == "secret" or any(k in title.lower() for k in ["secret", "password", "token", "key", "credential"]):
            for pattern in _SECRET_PATTERNS:
                if snippet:
                    result = run_static_check(snippet, pattern, label="secret")
                    if result["verdict"] == "VERIFIED":
                        return result
            # Try full code snippet
            code_text = snippet or vuln.get("raw_message", "")
            if code_text:
                return run_static_check(code_text, r"(?i)(password|api_key|secret|token)\s*=\s*['\"][^'\"]{4,}['\"]", "secret")
            return {
                "verdict": "SKIPPED", "method": "static_check",
                "container_image": "none", "command_executed": "",
                "exit_code": None, "stdout_excerpt": "", "stderr_excerpt": "",
                "timeout_hit": False, "duration_ms": 0,
                "notes": "No code snippet available for static pattern matching.",
            }

        # ── Profile: Dependency CVE ────────────────────────────────────────────
        if layer == "dependency":
            raw = vuln.get("raw_message", "") or vuln.get("description", "")
            # Try to extract package name and version from raw message
            import re
            pkg_match = re.search(r"([a-zA-Z0-9_\-\.]+)==?([0-9][0-9a-zA-Z\.\-]*)", raw)
            if pkg_match:
                pkg_name = pkg_match.group(1)
                pkg_ver  = pkg_match.group(2)
                cve_id   = vuln.get("title", "CVE-UNKNOWN")
                # Look for affected versions hint
                aff_match = re.search(r"[<>=!]+\s*[0-9][0-9a-zA-Z\.\-,\s]*", raw)
                aff_spec  = aff_match.group(0).strip() if aff_match else ""
                return run_dependency_check(pkg_name, pkg_ver, cve_id, aff_spec)
            return {
                "verdict": "INCONCLUSIVE", "method": "dependency_cve",
                "container_image": "none", "command_executed": "",
                "exit_code": None, "stdout_excerpt": "", "stderr_excerpt": "",
                "timeout_hit": False, "duration_ms": 0,
                "notes": "Could not extract package name/version from CVE data for comparison.",
            }

        # ── Profile: Python PoC snippet ───────────────────────────────────────
        if poc_code and len(poc_code.strip()) > 20:
            expected = self._infer_expected_pattern(owasp, title)
            return run_python_snippet(poc_code, expected_pattern=expected, label="poc")

        # ── Profile: Static code pattern for injection / auth ─────────────────
        if snippet and any(k in owasp for k in ["injection", "broken access", "auth"]):
            if "sql" in owasp or "injection" in title.lower():
                return run_static_check(snippet, r"(?i)(select|insert|update|delete).*\+.*\binput\b|f['\"].*select", "sqli")
            if "auth" in owasp:
                return run_static_check(snippet, r"(?i)(password\s*==|strcmp.*password|md5\(|sha1\()", "auth")

        # ── Default: SKIPPED ─────────────────────────────────────────────────
        return {
            "verdict": "SKIPPED", "method": "no_profile",
            "container_image": "none", "command_executed": "",
            "exit_code": None, "stdout_excerpt": "", "stderr_excerpt": "",
            "timeout_hit": False, "duration_ms": 0,
            "notes": "No suitable validation profile for this finding type.",
        }

    @staticmethod
    def _infer_expected_pattern(owasp: str, title: str) -> str:
        """Infer what output pattern indicates a successful exploit."""
        kw = (owasp + " " + title).lower()
        if "sql" in kw or "injection" in kw:
            return "error"   # SQL error = injection confirmed
        if "path" in kw or "traversal" in kw:
            return "root:"   # /etc/passwd output
        if "auth" in kw:
            return "success"
        return ""
