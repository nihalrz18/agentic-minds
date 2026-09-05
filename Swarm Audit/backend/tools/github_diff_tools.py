"""
GitHub diff utilities for SwarmAudit PR Guardian.
Handles changed-file parsing, diff formatting, and GitHub API helpers.
"""
import os
import re
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger("github_diff_tools")


def parse_changed_files(changed_files: List[str]) -> Dict[str, List[str]]:
    """
    Categorise changed files by risk type.
    Returns dict with keys: auth, crypto, config, deps, api, other.
    """
    categories: Dict[str, List[str]] = {
        "auth":   [],
        "crypto": [],
        "config": [],
        "deps":   [],
        "api":    [],
        "other":  [],
    }

    auth_patterns   = re.compile(r"auth|login|jwt|session|password|token|oauth|sso", re.I)
    crypto_patterns = re.compile(r"crypt|encrypt|hash|sign|cert|ssl|tls|key", re.I)
    config_patterns = re.compile(r"config|settings|\.env|docker|nginx|yaml|toml|json", re.I)
    dep_patterns    = re.compile(r"requirements|package\.json|package-lock|go\.mod|cargo\.toml|gemfile|pom\.xml", re.I)
    api_patterns    = re.compile(r"routes?|endpoint|api|views?|controller|handler", re.I)

    for f in changed_files:
        basename = os.path.basename(f).lower()
        if auth_patterns.search(f):
            categories["auth"].append(f)
        elif crypto_patterns.search(f):
            categories["crypto"].append(f)
        elif dep_patterns.search(basename):
            categories["deps"].append(f)
        elif config_patterns.search(f):
            categories["config"].append(f)
        elif api_patterns.search(f):
            categories["api"].append(f)
        else:
            categories["other"].append(f)

    return categories


def build_pr_comment_markdown(
    session_id: str,
    github_url: str,
    findings: List[Dict[str, Any]],
    validation_results: List[Dict[str, Any]],
    compliance_mappings: List[Dict[str, Any]],
    risk_data: Dict[str, Any],
    public_frontend_url: str = "",
) -> str:
    """
    Build a rich Markdown string for posting as a GitHub PR comment.
    """
    val_by_vuln: Dict[str, str] = {
        v.get("vuln_id", ""): v.get("verdict", "SKIPPED")
        for v in validation_results
    }
    comp_by_vuln: Dict[str, List[str]] = {}
    for m in compliance_mappings:
        vid = m.get("vuln_id", "")
        if vid not in comp_by_vuln:
            comp_by_vuln[vid] = []
        fw = m.get("framework", "")
        if fw and fw not in comp_by_vuln[vid]:
            comp_by_vuln[vid].append(fw)

    total_risk  = risk_data.get("total_risk_usd", 0)
    crit_count  = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count  = sum(1 for f in findings if f.get("severity") == "HIGH")
    verified    = sum(1 for v in validation_results if v.get("verdict") == "VERIFIED")

    verdict_emoji = {
        "VERIFIED":     "🔴 VERIFIED",
        "UNVERIFIED":   "🟡 UNVERIFIED",
        "INCONCLUSIVE": "🟠 INCONCLUSIVE",
        "SKIPPED":      "⚪ SKIPPED",
    }

    severity_emoji = {
        "CRITICAL": "🔴",
        "HIGH":     "🟠",
        "MEDIUM":   "🟡",
        "LOW":      "🟢",
        "INFO":     "⚪",
    }

    report_url = f"{public_frontend_url}/audit/{session_id}" if public_frontend_url else ""

    lines = [
        "## 🔐 SwarmAudit Security Scan Results",
        "",
        "> Automated security scan powered by [SwarmAudit](https://github.com/nihalrz18/swarm-audit) — "
        "evidence-backed, compliance-aware vulnerability analysis.",
        "",
        "### 📊 Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total Findings | **{len(findings)}** |",
        f"| Critical / High | **{crit_count} / {high_count}** |",
        f"| Verified Exploitable | **{verified}** |",
        f"| Estimated Exposure | **${total_risk:,.0f}** |",
        "",
    ]

    if findings:
        lines += [
            "### 🔍 Findings",
            "",
            "| Finding | Severity | Validation | Compliance Frameworks | Patch |",
            "|---------|----------|------------|----------------------|-------|",
        ]
        for f in findings[:15]:  # cap at 15 in comment
            vid      = f.get("id", "")
            title    = (f.get("title") or "Untitled")[:60]
            sev      = f.get("severity", "MEDIUM")
            sev_icon = severity_emoji.get(sev, "⚪")
            verdict  = verdict_emoji.get(val_by_vuln.get(vid, "SKIPPED"), "⚪ SKIPPED")
            fws      = ", ".join(comp_by_vuln.get(vid, [])[:3]) or "—"
            patch    = "✅ Available" if f.get("patch_diff") else "❌ None"
            lines.append(f"| {sev_icon} {title} | {sev} | {verdict} | {fws} | {patch} |")

        if len(findings) > 15:
            lines.append(f"| … | *{len(findings) - 15} more* | | | |")
        lines.append("")

    # Verified findings detail
    verified_findings = [
        f for f in findings
        if val_by_vuln.get(f.get("id", ""), "SKIPPED") == "VERIFIED"
    ]
    if verified_findings:
        lines += [
            "<details>",
            "<summary>🔴 Verified Exploitable Findings (click to expand)</summary>",
            "",
        ]
        for f in verified_findings[:5]:
            vid      = f.get("id", "")
            ev_list  = [v for v in validation_results if v.get("vuln_id") == vid]
            ev       = ev_list[0] if ev_list else {}
            lines += [
                f"#### {f.get('title', 'Untitled')}",
                f"- **Severity**: {f.get('severity')}",
                f"- **File**: `{f.get('file_path', 'unknown')}`",
                f"- **OWASP**: {f.get('owasp_category', 'N/A')}",
                "",
                f"> {f.get('description', '')[:300]}",
                "",
            ]
            if f.get("patch_diff"):
                lines += [
                    "**Suggested Fix:**",
                    "```diff",
                    f.get("patch_diff", "")[:600],
                    "```",
                    "",
                ]
            if ev.get("stdout_excerpt"):
                lines += [
                    "**Sandbox Evidence:**",
                    "```",
                    ev.get("stdout_excerpt", "")[:300],
                    "```",
                    "",
                ]
        lines += ["</details>", ""]

    if report_url:
        lines += [
            f"---",
            f"📄 [View Full Report]({report_url}) · "
            f"🔐 Scan by SwarmAudit",
            "",
        ]

    return "\n".join(lines)


def build_check_run_summary(
    findings: List[Dict[str, Any]],
    validation_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Determine the GitHub Check Run conclusion and build summary text.

    Returns: { conclusion: str, title: str, summary: str }
    """
    val_verdicts = {v.get("vuln_id", ""): v.get("verdict", "SKIPPED") for v in validation_results}

    verified_high = [
        f for f in findings
        if (f.get("severity") in ("CRITICAL", "HIGH"))
        and val_verdicts.get(f.get("id", ""), "SKIPPED") == "VERIFIED"
    ]
    inconclusive_high = [
        f for f in findings
        if (f.get("severity") in ("CRITICAL", "HIGH"))
        and val_verdicts.get(f.get("id", ""), "SKIPPED") in ("INCONCLUSIVE", "UNVERIFIED")
    ]

    if verified_high:
        conclusion = "action_required"
        title      = f"🔴 {len(verified_high)} verified high-risk finding(s)"
    elif inconclusive_high:
        conclusion = "neutral"
        title      = f"🟡 {len(inconclusive_high)} unconfirmed high-risk finding(s)"
    elif findings:
        conclusion = "success"
        title      = f"✅ {len(findings)} low-risk finding(s) — no critical exploitable issues"
    else:
        conclusion = "success"
        title      = "✅ No security findings detected"

    crit = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    med  = sum(1 for f in findings if f.get("severity") == "MEDIUM")

    summary = (
        f"SwarmAudit scanned {len(findings)} finding(s): "
        f"{crit} CRITICAL, {high} HIGH, {med} MEDIUM. "
        f"{len(verified_high)} confirmed exploitable by sandbox validation."
    )

    return {
        "conclusion": conclusion,
        "title":      title,
        "summary":    summary,
    }
