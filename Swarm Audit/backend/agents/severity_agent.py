"""
Severity Agent — Phase 4 (parallel).
Applies CVSS 3.1 scoring to all findings and produces severity statistics.
"""
from typing import Dict, Any, List


# CVSS 3.1 base score table for common vulnerability patterns
SEVERITY_MATRIX: Dict[str, Dict[str, Any]] = {
    "sql-injection": {
        "score": 9.8, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
    },
    "command-injection": {
        "score": 9.8, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
    },
    "xss": {
        "score": 6.1, "vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "severity": "MEDIUM",
    },
    "stored-xss": {
        "score": 8.8, "vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        "severity": "HIGH",
    },
    "ssrf": {
        "score": 8.6, "vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "severity": "HIGH",
    },
    "path-traversal": {
        "score": 7.5, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "severity": "HIGH",
    },
    "hardcoded-secret": {
        "score": 9.1, "vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "severity": "CRITICAL",
    },
    "auth-bypass": {
        "score": 9.8, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
    },
    "insecure-deserialization": {
        "score": 9.8, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "CRITICAL",
    },
    "prototype-pollution": {
        "score": 8.1, "vector": "AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "severity": "HIGH",
    },
    "unprotected-endpoint": {
        "score": 7.5, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "severity": "HIGH",
    },
    "dependency-cve": {
        "score": 7.0, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "severity": "HIGH",
    },
    "information-disclosure": {
        "score": 5.3, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "severity": "MEDIUM",
    },
    "csrf": {
        "score": 6.5, "vector": "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "severity": "MEDIUM",
    },
    "open-redirect": {
        "score": 6.1, "vector": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "severity": "MEDIUM",
    },
}

# Fallback by severity_raw
RAW_TO_CVSS = {
    "ERROR":   ("HIGH",   7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "WARNING": ("MEDIUM", 5.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "INFO":    ("LOW",    2.0, "AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"),
    "CRITICAL":("CRITICAL",9.8,"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "HIGH":    ("HIGH",   7.5, "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "MEDIUM":  ("MEDIUM", 5.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "LOW":     ("LOW",    2.0, "AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"),
}


class SeverityAgent:
    def __init__(self, llm_config: dict):
        self.llm_config = llm_config

    def run(self, all_findings: dict) -> Dict[str, Any]:
        vulns = all_findings.get("vulnerabilities", [])
        if not vulns:
            return {
                "scored_vulnerabilities": [],
                "critical_count": 0, "high_count": 0,
                "medium_count": 0,   "low_count":  0,
            }

        scored = [self._score(v) for v in vulns]
        scored.sort(key=lambda v: float(v.get("cvss_score", 0)), reverse=True)

        critical = sum(1 for v in scored if v["severity"] == "CRITICAL")
        high     = sum(1 for v in scored if v["severity"] == "HIGH")
        medium   = sum(1 for v in scored if v["severity"] == "MEDIUM")
        low      = sum(1 for v in scored if v["severity"] in ("LOW", "INFO"))

        return {
            "scored_vulnerabilities": scored,
            "critical_count": critical,
            "high_count":     high,
            "medium_count":   medium,
            "low_count":      low,
        }

    # ──────────────────────────────────────────────────────────────────────────
    def _score(self, vuln: dict) -> dict:
        v = dict(vuln)

        # If already has a reasonable CVSS score and vector, refine it
        existing_score  = float(v.get("cvss_score", 0))
        existing_vector = v.get("cvss_vector", "")

        # Try to lookup by title keywords
        title_lower = v.get("title", "").lower()
        matched = None
        for key, data in SEVERITY_MATRIX.items():
            if key.replace("-", " ") in title_lower or key in title_lower:
                matched = data
                break

        if matched and existing_score < matched["score"]:
            v["cvss_score"]  = matched["score"]
            v["cvss_vector"] = matched["vector"]
            v["severity"]    = matched["severity"]
        elif existing_score == 0:
            # Derive from severity_raw
            sev_raw = v.get("severity_raw", v.get("severity", "MEDIUM")).upper()
            sev_label, default_score, default_vec = RAW_TO_CVSS.get(
                sev_raw, ("MEDIUM", 5.0, "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
            )

            # Boost score if CRITICAL layer tags
            if v.get("layer") == "secret":
                default_score = max(default_score, 8.1)
                sev_label     = "HIGH" if sev_label not in ("CRITICAL",) else sev_label

            v["cvss_score"]  = default_score
            v["cvss_vector"] = existing_vector or default_vec
            v["severity"]    = sev_label

        # Normalise severity label
        score = float(v["cvss_score"])
        if score >= 9.0:
            v["severity"] = "CRITICAL"
        elif score >= 7.0:
            v["severity"] = "HIGH"
        elif score >= 4.0:
            v["severity"] = "MEDIUM"
        elif score > 0:
            v["severity"] = "LOW"
        else:
            v["severity"] = v.get("severity", "INFO")

        return v
