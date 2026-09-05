"""
API Agent — Phase 2 (parallel).
Discovers API endpoints across multiple frameworks and flags auth gaps.
"""
import os
import re
import uuid
from pathlib import Path
from typing import Dict, Any, List, Tuple

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", "target",
}

SENSITIVE_ROUTE_KEYWORDS = {
    "admin", "user", "users", "account", "accounts", "payment",
    "checkout", "billing", "password", "token", "secret", "internal",
    "config", "settings", "dashboard", "manage", "upload", "delete",
    "export", "import", "backup", "debug", "health", "metrics",
}

AUTH_DECORATORS = {
    # Flask / Python
    "@login_required", "@require_auth", "@jwt_required", "@token_required",
    "@auth_required", "@requires_auth", "@permission_required",
    "authenticate", "is_authenticated",
    # Django
    "login_required", "permission_required", "IsAuthenticated",
    "IsAdminUser", "SessionAuthentication",
    # FastAPI
    "Depends(get_current_user", "Depends(oauth2_scheme",
    "Security(", "HTTPBearer(", "APIKeyHeader(",
    # Express / Node
    "authenticate", "verifyToken", "isAuthenticated",
    "passport.authenticate", "authMiddleware", "requireAuth",
    # Spring
    "@PreAuthorize", "@Secured", "@RolesAllowed",
    "hasRole(", "isAuthenticated()",
}

# Framework patterns: (framework_name, route_regex)
ROUTE_PATTERNS: List[Tuple[str, str]] = [
    # Flask
    ("Flask",   r'@\w+\.route\(["\']([^"\']+)["\']'),
    ("Flask",   r'@blueprint\w*\.route\(["\']([^"\']+)["\']'),
    # FastAPI
    ("FastAPI", r'@\w+\.(get|post|put|patch|delete|options)\(["\']([^"\']+)["\']'),
    # Django URLs
    ("Django",  r'(?:path|re_path)\(["\']([^"\']*)["\']'),
    ("Django",  r'url\(["\']([^"\']+)["\']'),
    # Express / Node.js
    ("Express", r'(?:router|app)\.(get|post|put|patch|delete)\(["\']([^"\']+)["\']'),
    # Next.js API routes (file-based)
    ("Next.js", r'pages/api/([^\s]+)'),
    # Spring MVC
    ("Spring",  r'@(?:Request|Get|Post|Put|Delete|Patch)Mapping\(["\']([^"\']+)["\']'),
    ("Spring",  r'@(?:Request|Get|Post|Put|Delete|Patch)Mapping\(value\s*=\s*["\']([^"\']+)["\']'),
]


class APIAgent:
    def __init__(self, llm_config: dict):
        self.llm_config = llm_config

    def run(self, scan_result: dict) -> Dict[str, Any]:
        clone_path = scan_result.get("clone_path", "")
        if not clone_path or not os.path.exists(clone_path):
            return {"vulnerabilities": [], "error": "Clone path not found"}

        endpoints = self._discover_endpoints(clone_path)
        vulns     = self._flag_issues(endpoints, clone_path)
        return {"vulnerabilities": vulns, "endpoints_found": len(endpoints)}

    # ──────────────────────────────────────────────────────────────────────────
    def _discover_endpoints(self, clone_path: str) -> List[Dict[str, Any]]:
        endpoints = []
        for root, dirs, files in os.walk(clone_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                if Path(fname).suffix.lower() not in (
                    ".py", ".js", ".ts", ".java", ".rb", ".php", ".go", ".cs"
                ):
                    continue
                fpath    = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, clone_path)
                try:
                    content = open(fpath, encoding="utf-8", errors="ignore").read()
                    lines   = content.splitlines()
                except OSError:
                    continue

                for framework, pattern in ROUTE_PATTERNS:
                    for m in re.finditer(pattern, content, re.IGNORECASE):
                        # Get the route path from the match groups
                        route = m.group(2) if len(m.groups()) >= 2 else m.group(1)
                        if not route or len(route) > 200:
                            continue
                        # Find line number
                        start_char = m.start()
                        line_num   = content[:start_char].count("\n") + 1
                        # Check if auth is present in a 10-line window
                        window_start = max(0, line_num - 5)
                        window_end   = min(len(lines), line_num + 5)
                        window_text  = "\n".join(lines[window_start:window_end])
                        has_auth     = any(
                            a.lower() in window_text.lower()
                            for a in AUTH_DECORATORS
                        )
                        endpoints.append({
                            "route":      route,
                            "file_path":  rel_path,
                            "line_num":   line_num,
                            "framework":  framework,
                            "has_auth":   has_auth,
                            "method":     m.group(1) if len(m.groups()) >= 2 else "ANY",
                        })
        return endpoints

    def _flag_issues(self, endpoints: List[Dict], clone_path: str) -> List[Dict[str, Any]]:
        vulns = []
        for ep in endpoints:
            route     = ep["route"].lower()
            is_sens   = any(kw in route for kw in SENSITIVE_ROUTE_KEYWORDS)
            has_auth  = ep["has_auth"]

            if is_sens and not has_auth:
                method = str(ep.get("method", "ANY")).upper()
                vulns.append({
                    "id":    f"API-{uuid.uuid4().hex[:8]}",
                    "title": f"Unprotected sensitive endpoint: {ep['route']}",
                    "description": (
                        f"The {method} endpoint '{ep['route']}' ({ep['framework']}) "
                        f"appears to handle sensitive operations but lacks authentication "
                        f"middleware or decorators in the surrounding code."
                    ),
                    "file_path":      ep["file_path"],
                    "line_number":    ep["line_num"],
                    "severity":       "HIGH",
                    "severity_raw":   "WARNING",
                    "cvss_score":     7.5,
                    "cvss_vector":    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    "owasp_category": "A01:2021 - Broken Access Control",
                    "raw_message":    (
                        f"{ep['framework']} route {ep['route']} at line {ep['line_num']} "
                        "has no authentication guard."
                    ),
                    "code_snippet":   None,
                    "layer":          "api",
                    "references": [
                        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
                    ],
                    "endpoint":  ep["route"],
                    "framework": ep["framework"],
                })
            elif not has_auth and not is_sens:
                # Public endpoint — lower severity, info only
                pass  # Not flagged unless sensitive keyword present

        # Also flag: endpoints with no auth at all (mass exposure)
        no_auth_count  = sum(1 for e in endpoints if not e["has_auth"])
        total          = len(endpoints)
        if total > 0 and no_auth_count / total > 0.7 and no_auth_count > 3:
            vulns.append({
                "id":    f"API-{uuid.uuid4().hex[:8]}",
                "title": f"Mass missing authentication: {no_auth_count}/{total} endpoints unprotected",
                "description": (
                    f"{no_auth_count} out of {total} detected API endpoints appear to lack "
                    "authentication guards. This may indicate a systemic authentication failure."
                ),
                "file_path":      "",
                "line_number":    None,
                "severity":       "HIGH",
                "severity_raw":   "WARNING",
                "cvss_score":     8.1,
                "cvss_vector":    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "owasp_category": "A07:2021 - Identification and Authentication Failures",
                "raw_message":    f"Mass missing auth: {no_auth_count}/{total} endpoints",
                "code_snippet":   None,
                "layer":          "api",
                "references": [
                    "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
                ],
            })
        return vulns
