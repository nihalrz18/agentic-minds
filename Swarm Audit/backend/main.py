import asyncio
import json
import os
import uuid
from contextlib import asynccontextmanager
from typing import List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from database.connection import close_pool, fetch, fetchrow, execute
from database.migrations import run_migrations
from models.schemas import AuditRequest, PRScanRequest
from orchestrator.swarm_orchestrator import SwarmOrchestrator

load_dotenv()

INTERNAL_API_KEY = os.getenv("SWARMAUDIT_INTERNAL_API_KEY", "")


def _verify_internal_key(x_api_key: str = Header(default="")) -> None:
    """Validate the internal API key for machine-to-machine endpoints."""
    if INTERNAL_API_KEY and x_api_key != INTERNAL_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: run Neon DB migrations
    await run_migrations()
    yield
    # Shutdown: close DB pool
    await close_pool()


app = FastAPI(
    title="SwarmAudit API",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS — allow frontend on Vercel / Netlify + local dev
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Track active sessions for rate-limiting
active_sessions: dict[str, SwarmOrchestrator] = {}


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "service": "swarmaudit", "version": "2.0.0"}


# ── Start a new audit session ─────────────────────────────────────────────────
@app.post("/api/audit/start")
async def start_audit(request: AuditRequest):
    url = request.github_url.strip()
    if "github.com" not in url:
        raise HTTPException(status_code=400, detail="Must be a valid GitHub URL")

    # Simple rate limit: max 5 concurrent active sessions globally (free tier)
    if len(active_sessions) >= 5:
        raise HTTPException(
            status_code=429,
            detail="Too many active scans. Please wait for an existing scan to complete.",
        )

    session_id = str(uuid.uuid4())
    await execute(
        "INSERT INTO audit_sessions (id, github_url, status) VALUES ($1, $2, $3)",
        session_id, url, "pending",
    )
    return {"session_id": session_id, "status": "pending"}


# ── Start a PR-scoped audit ───────────────────────────────────────────────────
@app.post("/api/audit/start-pr-scan", dependencies=[Depends(_verify_internal_key)])
async def start_pr_scan(request: PRScanRequest):
    """
    Triggered by the GitHub Actions PR Guardian workflow.
    Initiates a PR-scoped audit, then posts a Check Run and PR comment.
    """
    if len(active_sessions) >= 5:
        raise HTTPException(
            status_code=429,
            detail="Too many active scans. Please wait.",
        )

    session_id = str(uuid.uuid4())
    await execute(
        "INSERT INTO audit_sessions (id, github_url, status, changed_files_only) "
        "VALUES ($1, $2, $3, $4)",
        session_id,
        request.github_url,
        "pending",
        True,
    )
    return {
        "session_id": session_id,
        "status":     "pending",
        "pr_number":  request.pr_number,
        "repo":       request.repo_full_name,
    }


# ── WebSocket: live agent streaming ──────────────────────────────────────────
@app.websocket("/ws/audit/{session_id}")
async def audit_websocket(websocket: WebSocket, session_id: str):
    await websocket.accept()
    orchestrator = SwarmOrchestrator(session_id, websocket)
    active_sessions[session_id] = orchestrator

    try:
        # Client must send {"github_url": "..."} immediately after connecting
        data = await asyncio.wait_for(websocket.receive_json(), timeout=30)
        github_url = data.get("github_url", "").strip()
        if not github_url:
            await websocket.send_json({"error": "github_url is required"})
            return

        # Mark as running
        await execute(
            "UPDATE audit_sessions SET status=$1 WHERE id=$2",
            "running", session_id,
        )

        await orchestrator.run(github_url)

        # Mark as complete
        await execute(
            "UPDATE audit_sessions SET status=$1, completed_at=NOW() WHERE id=$2",
            "completed", session_id,
        )

    except WebSocketDisconnect:
        pass
    except asyncio.TimeoutError:
        pass
    except Exception:
        try:
            await execute(
                "UPDATE audit_sessions SET status=$1 WHERE id=$2",
                "failed", session_id,
            )
        except Exception:
            pass
    finally:
        active_sessions.pop(session_id, None)


# ── WebSocket: PR-mode live agent streaming ───────────────────────────────────
@app.websocket("/ws/pr-audit/{session_id}")
async def pr_audit_websocket(websocket: WebSocket, session_id: str):
    """WebSocket endpoint for PR scans (includes GitHub Guardian phase)."""
    await websocket.accept()

    try:
        data          = await asyncio.wait_for(websocket.receive_json(), timeout=30)
        github_url    = data.get("github_url", "").strip()
        pr_number     = int(data.get("pr_number", 0))
        pr_sha        = data.get("sha", "").strip()
        repo_full     = data.get("repo_full_name", "").strip()
        changed_files = data.get("changed_files", [])
        gh_token      = data.get("github_token", "").strip() or os.getenv("GITHUB_TOKEN", "")

        if not github_url:
            await websocket.send_json({"error": "github_url is required"})
            return

        orchestrator = SwarmOrchestrator(
            session_id      = session_id,
            websocket       = websocket,
            pr_mode         = True,
            pr_number       = pr_number,
            pr_sha          = pr_sha,
            repo_full_name  = repo_full,
            changed_files   = changed_files,
            github_token    = gh_token,
        )
        active_sessions[session_id] = orchestrator

        await execute(
            "UPDATE audit_sessions SET status=$1 WHERE id=$2",
            "running", session_id,
        )

        await orchestrator.run(github_url)

        await execute(
            "UPDATE audit_sessions SET status=$1, completed_at=NOW() WHERE id=$2",
            "completed", session_id,
        )

    except WebSocketDisconnect:
        pass
    except asyncio.TimeoutError:
        pass
    except Exception:
        try:
            await execute(
                "UPDATE audit_sessions SET status=$1 WHERE id=$2",
                "failed", session_id,
            )
        except Exception:
            pass
    finally:
        active_sessions.pop(session_id, None)


# ── Session status ────────────────────────────────────────────────────────────
@app.get("/api/audit/{session_id}/status")
async def get_status(session_id: str):
    row = await fetchrow(
        "SELECT id, github_url, status, total_vulnerabilities, "
        "critical_count, high_count, medium_count, low_count, "
        "total_risk_usd, repo_name, tech_stack, file_count, "
        "pr_status, created_at, completed_at "
        "FROM audit_sessions WHERE id=$1",
        session_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")
    return dict(row)


# ── Validation results ────────────────────────────────────────────────────────
@app.get("/api/audit/{session_id}/validation")
async def get_validation(session_id: str):
    row = await fetchrow(
        "SELECT id FROM audit_sessions WHERE id=$1", session_id
    )
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")

    rows = await fetch(
        "SELECT vuln_id, verdict, method, container_image, command_executed, "
        "exit_code, stdout_excerpt, stderr_excerpt, timeout_hit, duration_ms, notes "
        "FROM validation_results WHERE session_id=$1 ORDER BY created_at",
        session_id,
    )
    return {"session_id": session_id, "validation_results": [dict(r) for r in (rows or [])]}


# ── Compliance mappings ───────────────────────────────────────────────────────
@app.get("/api/audit/{session_id}/compliance")
async def get_compliance(session_id: str):
    row = await fetchrow(
        "SELECT id FROM audit_sessions WHERE id=$1", session_id
    )
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")

    rows = await fetch(
        "SELECT vuln_id, framework, control_id, control_name, owasp_category, rationale "
        "FROM compliance_mappings WHERE session_id=$1 ORDER BY framework, control_id",
        session_id,
    )
    mappings = [dict(r) for r in (rows or [])]

    # Compute blast radius client-side is fine, but also serve it from DB data
    from tools.compliance_mappings import get_compliance_blast_radius
    blast = get_compliance_blast_radius(mappings)

    return {
        "session_id":        session_id,
        "compliance_mappings": mappings,
        "blast_radius":      blast,
    }


# ── Report deep-link ──────────────────────────────────────────────────────────
@app.get("/api/audit/{session_id}/report-link")
async def get_report_link(session_id: str):
    row = await fetchrow(
        "SELECT id, status FROM audit_sessions WHERE id=$1", session_id
    )
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")
    public_url = os.getenv("PUBLIC_FRONTEND_URL", "")
    return {
        "session_id":   session_id,
        "status":       row["status"],
        "report_url":   f"{public_url}/audit/{session_id}" if public_url else "",
        "pdf_url":      f"{os.getenv('PUBLIC_BACKEND_URL', '')}/api/report/{session_id}/download",
    }


# ── PDF report download ───────────────────────────────────────────────────────
@app.get("/api/report/{session_id}/download")
async def download_report(session_id: str):
    # Validate session exists
    row = await fetchrow("SELECT id FROM audit_sessions WHERE id=$1", session_id)
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")

    report_path = f"/tmp/reports/{session_id}_report.pdf"
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="Report not ready yet")

    return FileResponse(
        report_path,
        media_type="application/pdf",
        filename=f"swarmaudit_{session_id[:8]}.pdf",
    )
