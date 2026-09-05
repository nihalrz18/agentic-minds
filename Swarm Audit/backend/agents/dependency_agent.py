"""
Dependency Agent — Phase 2 (parallel).
Parses manifest files and queries OSV.dev for known CVEs.
"""
import os
import re
import json
import uuid
import time
import httpx
from pathlib import Path
from typing import Dict, Any, List, Optional


OSV_API = "https://api.osv.dev/v1/query"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

ECOSYSTEM_MAP = {
    "requirements.txt": "PyPI",
    "Pipfile":           "PyPI",
    "pyproject.toml":   "PyPI",
    "package.json":     "npm",
    "yarn.lock":        "npm",
    "pom.xml":          "Maven",
    "build.gradle":     "Maven",
    "go.mod":           "Go",
    "Cargo.toml":       "crates.io",
    "Gemfile":          "RubyGems",
    "composer.json":    "Packagist",
}


class DependencyAgent:
    def __init__(self, llm_config: dict):
        self.llm_config = llm_config

    def run(self, scan_result: dict) -> Dict[str, Any]:
        clone_path = scan_result.get("clone_path", "")
        if not clone_path or not os.path.exists(clone_path):
            return {"vulnerabilities": [], "error": "Clone path not found"}

        packages = self._parse_manifests(clone_path)
        if not packages:
            return {"vulnerabilities": [], "packages_scanned": 0}

        vulns = self._query_osv(packages)
        return {"vulnerabilities": vulns, "packages_scanned": len(packages)}

    # ──────────────────────────────────────────────────────────────────────────
    def _parse_manifests(self, clone_path: str) -> List[Dict[str, str]]:
        packages = []
        for fname, ecosystem in ECOSYSTEM_MAP.items():
            fpath = os.path.join(clone_path, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                content = open(fpath, encoding="utf-8", errors="ignore").read()
                parsed = self._parse_file(fname, content, ecosystem)
                packages.extend(parsed)
            except OSError:
                continue
        return packages

    def _parse_file(self, fname: str, content: str, ecosystem: str) -> List[Dict[str, str]]:
        pkgs = []
        if fname == "requirements.txt":
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^([A-Za-z0-9_\-\.]+)[=><!\s]*([0-9][0-9a-zA-Z.\-]*)?", line)
                if m:
                    pkgs.append({"name": m.group(1), "version": m.group(2) or "", "ecosystem": ecosystem})

        elif fname == "package.json":
            try:
                data = json.loads(content)
                for dep_section in ("dependencies", "devDependencies"):
                    for name, ver in data.get(dep_section, {}).items():
                        clean_ver = re.sub(r"[^0-9a-zA-Z.\-]", "", ver)[:20]
                        pkgs.append({"name": name, "version": clean_ver, "ecosystem": ecosystem})
            except json.JSONDecodeError:
                pass

        elif fname == "go.mod":
            for line in content.splitlines():
                line = line.strip()
                m = re.match(r"^\s*([a-zA-Z0-9_.\/\-]+)\s+v([0-9][0-9a-zA-Z.\-]+)", line)
                if m:
                    pkgs.append({"name": m.group(1), "version": m.group(2), "ecosystem": ecosystem})

        elif fname == "Cargo.toml":
            for line in content.splitlines():
                m = re.match(r'^([a-zA-Z0-9_\-]+)\s*=\s*["\']([0-9][^"\']*)["\']', line)
                if m:
                    pkgs.append({"name": m.group(1), "version": m.group(2), "ecosystem": ecosystem})

        elif fname == "Gemfile":
            for line in content.splitlines():
                m = re.match(r"^\s*gem\s+['\"]([^'\"]+)['\"](?:,\s*['\"]([^'\"]+)['\"])?", line)
                if m:
                    pkgs.append({"name": m.group(1), "version": m.group(2) or "", "ecosystem": ecosystem})

        elif fname in ("pom.xml", "build.gradle"):
            # Extract artifact IDs from Maven/Gradle
            for m in re.finditer(r"<artifactId>([^<]+)</artifactId>", content):
                pkgs.append({"name": m.group(1), "version": "", "ecosystem": ecosystem})

        elif fname == "composer.json":
            try:
                data = json.loads(content)
                for name, ver in data.get("require", {}).items():
                    pkgs.append({"name": name, "version": ver, "ecosystem": ecosystem})
            except json.JSONDecodeError:
                pass

        return pkgs[:60]  # Limit per manifest to avoid rate limiting

    def _query_osv(self, packages: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        vulns = []
        with httpx.Client(timeout=15) as client:
            for pkg in packages[:40]:  # Cap total API calls on free tier
                name    = pkg["name"]
                version = pkg["version"]
                eco     = pkg["ecosystem"]
                if not name:
                    continue
                try:
                    payload: Dict[str, Any] = {"package": {"name": name, "ecosystem": eco}}
                    if version:
                        payload["version"] = version
                    resp = client.post(OSV_API, json=payload)
                    if resp.status_code != 200:
                        time.sleep(0.2)
                        continue
                    data = resp.json()
                    for osv_vuln in data.get("vulns", []):
                        severity, cvss_score, cvss_vec = self._extract_severity(osv_vuln)
                        desc = osv_vuln.get("details", "")[:500]
                        aliases = osv_vuln.get("aliases", [])
                        cve_id  = next((a for a in aliases if a.startswith("CVE-")), osv_vuln.get("id", ""))
                        vulns.append({
                            "id":             f"DEP-{uuid.uuid4().hex[:8]}",
                            "title":          f"{name} {version} — {cve_id}",
                            "description":    desc or f"Known vulnerability in {name} {version}",
                            "file_path":      f"package: {name}@{version}",
                            "line_number":    None,
                            "severity":       severity,
                            "severity_raw":   "ERROR" if severity in ("CRITICAL","HIGH") else "WARNING",
                            "cvss_score":     cvss_score,
                            "cvss_vector":    cvss_vec,
                            "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
                            "raw_message":    f"OSV ID: {osv_vuln.get('id','')} | CVE: {cve_id}",
                            "code_snippet":   None,
                            "layer":          "dependency",
                            "references":     [
                                f"https://osv.dev/vulnerability/{osv_vuln.get('id','')}",
                                f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id.startswith("CVE-") else "",
                            ],
                            "package_name":   name,
                            "package_version": version,
                            "ecosystem":      eco,
                        })
                    time.sleep(0.1)  # polite delay for free tier
                except (httpx.RequestError, Exception):
                    time.sleep(0.2)
                    continue
        return vulns

    def _extract_severity(self, osv_vuln: dict):
        """Extract CVSS severity from OSV vulnerability record."""
        severity = "MEDIUM"
        cvss_score = 5.0
        cvss_vec   = ""

        for sev_entry in osv_vuln.get("severity", []):
            s_type  = sev_entry.get("type", "")
            s_score = sev_entry.get("score", "")
            if s_type in ("CVSS_V3", "CVSS_V31"):
                cvss_vec = s_score
                # Extract numeric score from vector or try database_specific
                break

        # Try database_specific CVSS
        db = osv_vuln.get("database_specific", {})
        score_str = str(db.get("cvss", "") or db.get("cvss_score", ""))
        if score_str:
            try:
                cvss_score = float(score_str)
            except ValueError:
                pass

        if cvss_score >= 9.0:
            severity = "CRITICAL"
        elif cvss_score >= 7.0:
            severity = "HIGH"
        elif cvss_score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return severity, cvss_score, cvss_vec
