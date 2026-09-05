"""
Ephemeral Docker sandbox runner for SwarmAudit exploit validation.

Runs PoC snippets in locked-down, network-isolated containers and
returns structured evidence (exit code, stdout/stderr excerpt, verdict).

Gracefully degrades to SKIPPED when:
  - Docker daemon is unavailable (e.g., Render free tier)
  - The exploit requires live network access
  - The PoC type is not safe to automate
"""
import os
import time
import tempfile
import textwrap
import logging
from typing import Any, Dict

logger = logging.getLogger("sandbox_runner")

# ─── Docker availability check ────────────────────────────────────────────────
try:
    import docker  # type: ignore
    _client = docker.from_env(timeout=5)
    _client.ping()
    DOCKER_AVAILABLE = True
    logger.info("Docker daemon available — sandbox validation enabled.")
except Exception as _e:
    DOCKER_AVAILABLE = False
    logger.warning(f"Docker daemon unavailable — sandbox validation disabled: {_e}")

SANDBOX_IMAGE       = "python:3.11-slim"
VALIDATION_TIMEOUT  = int(os.getenv("VALIDATION_TIMEOUT_SECONDS", "20"))
MEMORY_LIMIT        = "256m"
CPU_PERIOD          = 100_000   # 100ms
CPU_QUOTA           = 25_000    # 25% of one CPU
PIDS_LIMIT          = 32

# ─── Sanitise PoC code before execution ──────────────────────────────────────
_BLOCKED_PATTERNS = [
    "import socket", "import requests", "import urllib", "import httpx",
    "import aiohttp", "import ftplib", "import smtplib", "import telnetlib",
    "open('/etc", "open('/proc", "open('/sys", "subprocess.call",
    "subprocess.Popen", "os.system", "eval(", "exec(",
    "__import__", "importlib",
]


def _is_safe_to_run(code: str) -> bool:
    code_lower = code.lower()
    for pattern in _BLOCKED_PATTERNS:
        if pattern.lower() in code_lower:
            return False
    # Reject if code looks like it needs network
    if any(k in code_lower for k in ["http://", "https://", "127.0.0.1", "localhost"]):
        return False
    return True


def _truncate(text: str, max_chars: int = 1500) -> str:
    return text[:max_chars] + ("…" if len(text) > max_chars else "")


# ─── Sandbox execution ────────────────────────────────────────────────────────

def run_python_snippet(
    code: str,
    expected_pattern: str = "",
    label: str = "poc",
) -> Dict[str, Any]:
    """
    Run a Python code snippet in an ephemeral, locked-down Docker container.

    Returns:
        {
            verdict: VERIFIED | UNVERIFIED | INCONCLUSIVE | SKIPPED,
            method: python_snippet,
            container_image: str,
            command_executed: str,
            exit_code: int | None,
            stdout_excerpt: str,
            stderr_excerpt: str,
            timeout_hit: bool,
            duration_ms: int,
            notes: str,
        }
    """
    base_result = {
        "method":          "python_snippet",
        "container_image": SANDBOX_IMAGE,
        "command_executed": "",
        "exit_code":        None,
        "stdout_excerpt":   "",
        "stderr_excerpt":   "",
        "timeout_hit":      False,
        "duration_ms":      0,
        "notes":            "",
    }

    if not DOCKER_AVAILABLE:
        return {**base_result, "verdict": "SKIPPED",
                "notes": "Docker daemon not available on this host. Sandbox validation is disabled."}

    if not code or len(code.strip()) < 5:
        return {**base_result, "verdict": "SKIPPED",
                "notes": "No exploitable PoC code provided for this finding."}

    if not _is_safe_to_run(code):
        return {**base_result, "verdict": "SKIPPED",
                "notes": "PoC requires network access or unsafe system calls — skipped for safety."}

    # Write code to a temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, prefix=f"swarmaudit_{label}_"
    ) as f:
        f.write(textwrap.dedent(code))
        tmp_path = f.name

    start = time.time()
    container = None
    try:
        client = docker.from_env(timeout=5)

        # Mount only the script — read-only host filesystem
        volumes = {tmp_path: {"bind": "/sandbox/exploit.py", "mode": "ro"}}
        command = ["python", "/sandbox/exploit.py"]

        base_result["command_executed"] = "python /sandbox/exploit.py"

        container = client.containers.run(
            SANDBOX_IMAGE,
            command=command,
            volumes=volumes,
            network_disabled=True,
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            mem_limit=MEMORY_LIMIT,
            cpu_period=CPU_PERIOD,
            cpu_quota=CPU_QUOTA,
            pids_limit=PIDS_LIMIT,
            tmpfs={"/tmp": "size=32m,exec"},
            user="nobody",
            remove=False,
            detach=True,
            stdin_open=False,
            tty=False,
        )

        # Wait with timeout
        try:
            result = container.wait(timeout=VALIDATION_TIMEOUT)
            exit_code = result.get("StatusCode", -1)
            timeout_hit = False
        except Exception:
            exit_code = -1
            timeout_hit = True
            try:
                container.kill()
            except Exception:
                pass

        duration_ms = int((time.time() - start) * 1000)

        # Collect logs
        try:
            raw_logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
            stdout_text = _truncate(raw_logs)
        except Exception:
            stdout_text = ""
            raw_logs = ""

        try:
            container.remove(force=True)
        except Exception:
            pass

        # Determine verdict
        if timeout_hit:
            verdict = "INCONCLUSIVE"
            notes = "Container execution timed out — exploit may require interactive input or long execution."
        elif exit_code == 0:
            if expected_pattern and expected_pattern.lower() in raw_logs.lower():
                verdict = "VERIFIED"
                notes = f"Expected pattern '{expected_pattern}' found in output. Exploit confirmed in sandbox."
            elif expected_pattern:
                verdict = "UNVERIFIED"
                notes = f"Script ran successfully (exit 0) but expected pattern '{expected_pattern}' not found."
            else:
                verdict = "VERIFIED"
                notes = "Script executed cleanly (exit 0). Exploit logic ran without errors."
        else:
            verdict = "UNVERIFIED"
            notes = f"Script exited with code {exit_code}. Exploit did not execute as expected."

        return {
            **base_result,
            "verdict":        verdict,
            "exit_code":      exit_code,
            "stdout_excerpt": stdout_text,
            "stderr_excerpt": "",
            "timeout_hit":    timeout_hit,
            "duration_ms":    duration_ms,
            "notes":          notes,
        }

    except Exception as exc:
        duration_ms = int((time.time() - start) * 1000)
        if container:
            try:
                container.remove(force=True)
            except Exception:
                pass
        return {
            **base_result,
            "verdict":     "INCONCLUSIVE",
            "duration_ms": duration_ms,
            "notes":       f"Sandbox execution error: {str(exc)[:300]}",
        }
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def run_static_check(
    finding_text: str,
    pattern: str,
    label: str = "static",
) -> Dict[str, Any]:
    """
    Validate a finding using simple regex/text pattern matching (no Docker).
    Used for hardcoded secrets and simple static findings.
    """
    import re
    base = {
        "method":          "static_check",
        "container_image": "none",
        "command_executed": f"regex match: {pattern[:80]}",
        "exit_code":        None,
        "timeout_hit":      False,
        "duration_ms":      1,
    }
    try:
        match = re.search(pattern, finding_text, re.IGNORECASE | re.DOTALL)
        if match:
            return {
                **base,
                "verdict":        "VERIFIED",
                "stdout_excerpt": f"Pattern matched: '{match.group(0)[:200]}'",
                "stderr_excerpt": "",
                "notes":          "Static pattern confirmed the finding in source code.",
            }
        return {
            **base,
            "verdict":        "UNVERIFIED",
            "stdout_excerpt": "",
            "stderr_excerpt": "",
            "notes":          "Static pattern did not match — finding may be a false positive.",
        }
    except re.error as e:
        return {
            **base,
            "verdict":        "INCONCLUSIVE",
            "stdout_excerpt": "",
            "stderr_excerpt": "",
            "notes":          f"Invalid regex pattern: {e}",
        }


def run_dependency_check(
    package_name: str,
    installed_version: str,
    cve_id: str,
    affected_versions: str = "",
) -> Dict[str, Any]:
    """
    Validate a dependency CVE by comparing installed version to affected range.
    Uses packaging library for semver comparison.
    """
    base = {
        "method":          "dependency_cve",
        "container_image": "none",
        "command_executed": f"semver check: {package_name}=={installed_version} vs {affected_versions}",
        "exit_code":        None,
        "timeout_hit":      False,
        "duration_ms":      1,
        "stderr_excerpt":   "",
    }
    try:
        from packaging.version import Version
        from packaging.specifiers import SpecifierSet

        if not affected_versions or not installed_version:
            return {
                **base,
                "verdict":        "INCONCLUSIVE",
                "stdout_excerpt": "",
                "notes":          "Cannot determine affected version range — CVE data incomplete.",
            }

        spec = SpecifierSet(affected_versions)
        v = Version(installed_version)
        if v in spec:
            return {
                **base,
                "verdict":        "VERIFIED",
                "stdout_excerpt": f"{package_name}=={installed_version} is in affected range {affected_versions}",
                "notes":          f"Installed version confirmed vulnerable per {cve_id} spec.",
            }
        return {
            **base,
            "verdict":        "UNVERIFIED",
            "stdout_excerpt": f"{package_name}=={installed_version} outside affected range {affected_versions}",
            "notes":          "Installed version is NOT in the affected range — may be safe or patched.",
        }
    except Exception as e:
        return {
            **base,
            "verdict":        "INCONCLUSIVE",
            "stdout_excerpt": "",
            "notes":          f"Version comparison error: {e}",
        }
