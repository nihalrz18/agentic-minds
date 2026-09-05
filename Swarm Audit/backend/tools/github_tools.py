"""
GitHub utility helpers for SwarmAudit.
Provides URL parsing and repo metadata retrieval.
"""
import re
import os
from typing import Optional, Tuple


def parse_github_url(url: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse a GitHub URL and return (owner, repo_name).
    Returns (None, None) if the URL is invalid.
    """
    pattern = r"https://github\.com/([^/]+)/([^/\s]+?)(?:\.git)?(?:/.*)?$"
    m = re.match(pattern, url.strip())
    if not m:
        return None, None
    owner = m.group(1)
    repo = m.group(2).rstrip("/")
    return owner, repo


def is_valid_github_url(url: str) -> bool:
    """Return True if the URL looks like a valid public GitHub repo URL."""
    owner, repo = parse_github_url(url)
    return bool(owner and repo)


def get_clone_path(repo_name: str, owner: str) -> str:
    """Return deterministic temp path for the cloned repo."""
    safe_owner = re.sub(r"[^a-zA-Z0-9_-]", "_", owner)[:16]
    safe_repo  = re.sub(r"[^a-zA-Z0-9_-]", "_", repo_name)[:32]
    return f"/tmp/swarmaudit_{safe_owner}_{safe_repo}"


def mask_secret(value: str) -> str:
    """Mask the middle portion of a secret value for safe logging."""
    if len(value) <= 8:
        return "****"
    visible = max(4, len(value) // 5)
    return value[:visible] + "****" + value[-visible:]
