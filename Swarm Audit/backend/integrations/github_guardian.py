"""
GitHub Guardian integration.
Posts PR comments and creates/updates Check Runs via PyGithub.
"""
import logging
import os
from typing import Any, Dict, List, Optional

from github import Github, GithubException  # type: ignore

from tools.github_diff_tools import (
    build_check_run_summary,
    build_pr_comment_markdown,
)

logger = logging.getLogger("github_guardian")

PUBLIC_FRONTEND_URL = os.getenv("PUBLIC_FRONTEND_URL", "")
SWARMAUDIT_BOT_NAME = "swarmaudit-security[bot]"
CHECK_RUN_NAME      = "SwarmAudit Security Scan"


def _get_github(token: str) -> Github:
    return Github(token)


def post_pr_security_comment(
    token: str,
    repo_full_name: str,
    pr_number: int,
    session_id: str,
    findings: List[Dict[str, Any]],
    validation_results: List[Dict[str, Any]],
    compliance_mappings: List[Dict[str, Any]],
    risk_data: Dict[str, Any],
    delete_previous: bool = True,
) -> Dict[str, Any]:
    """
    Post (or update) a security summary comment on a GitHub Pull Request.

    Args:
        token:               GitHub personal access token or Actions ${{ secrets.GITHUB_TOKEN }}
        repo_full_name:      e.g. "owner/repo"
        pr_number:           Pull request number
        session_id:          SwarmAudit session UUID (for deep-link)
        findings:            List of Vulnerability dicts
        validation_results:  List of ValidationEvidence dicts
        compliance_mappings: List of ComplianceMapping dicts
        risk_data:           risk summary dict (total_risk_usd, etc.)
        delete_previous:     Remove prior SwarmAudit bot comments before posting

    Returns:
        { "success": bool, "comment_url": str, "error": str }
    """
    try:
        gh    = _get_github(token)
        repo  = gh.get_repo(repo_full_name)
        pr    = repo.get_pull(pr_number)

        body = build_pr_comment_markdown(
            session_id          = session_id,
            github_url          = pr.html_url,
            findings            = findings,
            validation_results  = validation_results,
            compliance_mappings = compliance_mappings,
            risk_data           = risk_data,
            public_frontend_url = PUBLIC_FRONTEND_URL,
        )

        # Optionally delete previous SwarmAudit comments to avoid clutter
        if delete_previous:
            for comment in pr.get_issue_comments():
                if "SwarmAudit Security Scan Results" in (comment.body or ""):
                    try:
                        comment.delete()
                    except GithubException:
                        pass

        comment = pr.create_issue_comment(body)
        return {
            "success":     True,
            "comment_url": comment.html_url,
            "error":       "",
        }
    except GithubException as e:
        logger.error(f"GitHub PR comment failed [{repo_full_name}#{pr_number}]: {e}")
        return {
            "success":     False,
            "comment_url": "",
            "error":       str(e),
        }
    except Exception as e:
        logger.error(f"Unexpected error posting PR comment: {e}")
        return {
            "success":     False,
            "comment_url": "",
            "error":       str(e),
        }


def create_or_update_check_run(
    token: str,
    repo_full_name: str,
    sha: str,
    session_id: str,
    findings: List[Dict[str, Any]],
    validation_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Create or update a GitHub Check Run for a specific commit SHA.

    Conclusions:
        "action_required" — verified high/critical findings
        "neutral"         — unverified high/critical findings
        "success"         — no critical exploitable issues

    Returns:
        { "success": bool, "check_run_url": str, "conclusion": str, "error": str }
    """
    try:
        gh   = _get_github(token)
        repo = gh.get_repo(repo_full_name)

        summary_data = build_check_run_summary(findings, validation_results)
        conclusion   = summary_data["conclusion"]

        report_url = f"{PUBLIC_FRONTEND_URL}/audit/{session_id}" if PUBLIC_FRONTEND_URL else ""
        actions = []
        if conclusion == "action_required" and report_url:
            actions = [{
                "label":       "View Full Report",
                "description": "Open SwarmAudit report",
                "identifier":  "view_report",
            }]

        # Build annotation list (first 50 critical/high findings)
        annotations = []
        for f in findings[:50]:
            sev = f.get("severity", "LOW")
            if sev not in ("CRITICAL", "HIGH", "MEDIUM"):
                continue
            ann_level = "failure" if sev in ("CRITICAL", "HIGH") else "warning"
            file_path = f.get("file_path") or f.get("file", "")
            if not file_path:
                continue
            annotations.append({
                "path":             file_path.lstrip("/"),
                "start_line":       f.get("line_number", 1) or 1,
                "end_line":         f.get("line_number", 1) or 1,
                "annotation_level": ann_level,
                "message":          f"{f.get('title', 'Security Finding')}: {f.get('description', '')[:200]}",
                "title":            f"{sev}: {f.get('title', 'Security Finding')[:60]}",
            })

        output: Dict[str, Any] = {
            "title":        summary_data["title"],
            "summary":      summary_data["summary"],
        }
        if annotations:
            output["annotations"] = annotations

        check_run = repo.create_check_run(
            name       = CHECK_RUN_NAME,
            head_sha   = sha,
            status     = "completed",
            conclusion = conclusion,
            output     = output,
        )
        return {
            "success":       True,
            "check_run_url": check_run.html_url,
            "conclusion":    conclusion,
            "error":         "",
        }
    except GithubException as e:
        logger.error(f"GitHub Check Run failed [{repo_full_name}@{sha[:7]}]: {e}")
        return {
            "success":       False,
            "check_run_url": "",
            "conclusion":    "neutral",
            "error":         str(e),
        }
    except Exception as e:
        logger.error(f"Unexpected error creating check run: {e}")
        return {
            "success":       False,
            "check_run_url": "",
            "conclusion":    "neutral",
            "error":         str(e),
        }


def get_pr_changed_files(
    token: str,
    repo_full_name: str,
    pr_number: int,
) -> List[str]:
    """
    Return list of file paths changed in a pull request.
    """
    try:
        gh   = _get_github(token)
        repo = gh.get_repo(repo_full_name)
        pr   = repo.get_pull(pr_number)
        return [f.filename for f in pr.get_files()]
    except Exception as e:
        logger.error(f"get_pr_changed_files failed: {e}")
        return []
