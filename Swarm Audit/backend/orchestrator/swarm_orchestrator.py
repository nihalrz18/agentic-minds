"""
SwarmOrchestrator — runs the multi-agent security audit swarm.
Phases 1-4: Scan → SAST/Dep/Secrets/API → AttackChain → PoC/Sev/Patch/Risk
Phase 5: Validation (sandbox exploit verification)
Phase 6: Compliance (SOC2/HIPAA/PCI-DSS/GDPR/MITRE mapping)
Phase 7: Report (PDF generation)
Phase 8 (PR mode only): GitHub Guardian (PR comment + Check Run)
"""
import asyncio
import json
import gc
import os
import shutil
import time
from typing import List, Optional
from fastapi import WebSocket

from database.connection import execute
from tools.report_generator import generate_pdf_report

from agents.scanner_agent import ScannerAgent
from agents.sast_agent import SASTAgent
from agents.dependency_agent import DependencyAgent
from agents.secrets_agent import SecretsAgent
from agents.api_agent import APIAgent
from agents.attack_chain_agent import AttackChainAgent
from agents.poc_agent import PoCAgent
from agents.severity_agent import SeverityAgent
from agents.patch_agent import PatchAgent
from agents.risk_agent import RiskAgent
from agents.report_agent import ReportAgent
from agents.validation_agent import ValidationAgent
from agents.compliance_agent import ComplianceAgent


class SwarmOrchestrator:
    def __init__(
        self,
        session_id: str,
        websocket: WebSocket,
        pr_mode: bool = False,
        pr_number: Optional[int] = None,
        pr_sha: Optional[str] = None,
        repo_full_name: Optional[str] = None,
        changed_files: Optional[List[str]] = None,
        github_token: Optional[str] = None,
    ):
        self.session_id      = session_id
        self.websocket       = websocket
        self.pr_mode         = pr_mode
        self.pr_number       = pr_number
        self.pr_sha          = pr_sha
        self.repo_full_name  = repo_full_name
        self.changed_files   = changed_files or []
        self.github_token    = github_token or os.getenv("GITHUB_TOKEN", "")
        self.llm_config = {
            "config_list": [
                {
                    "model":    "llama-3.3-70b-versatile",
                    "api_key":  os.getenv("GROQ_API_KEY"),
                    "base_url": "https://api.groq.com/openai/v1",
                    "api_type": "openai",
                }
            ],
            "temperature": 0.1,
            "max_tokens":  2048,
        }

    # ── WebSocket event helper ─────────────────────────────────────────────────
    async def send_event(
        self,
        agent_name: str,
        agent_type: str,
        status: str,
        message: str,
        data=None,
    ):
        try:
            await self.websocket.send_json(
                {
                    "agent_name": agent_name,
                    "agent_type": agent_type,
                    "status":     status,
                    "message":    message,
                    "data":       data,
                    "timestamp":  time.time(),
                }
            )
        except Exception:
            pass  # Client disconnected — fail silently

    # ── Graceful result unwrap ─────────────────────────────────────────────────
    @staticmethod
    def _safe(result, default):
        return result if not isinstance(result, Exception) else default

    # ── Main orchestration flow ────────────────────────────────────────────────
    async def run(self, github_url: str):
        clone_path = None
        try:
            # ═══════════════════════════════════════════════════════════════
            # PHASE 1: Scanner
            # ═══════════════════════════════════════════════════════════════
            await self.send_event(
                "Scanner", "scanner", "thinking",
                "Cloning repository and mapping file structure…",
            )
            scan_result = await asyncio.wait_for(
                asyncio.to_thread(ScannerAgent(self.llm_config).run, github_url),
                timeout=120,
            )

            if not scan_result.get("scan_complete"):
                err = scan_result.get("error", "Scan failed")
                await self.send_event("Scanner", "scanner", "error", err)
                return

            clone_path = scan_result.get("clone_path")
            await self.send_event(
                "Scanner", "scanner", "done",
                f"Mapped {scan_result['file_count']} files. "
                f"Stack: {', '.join(scan_result['tech_stack'])}",
                scan_result,
            )

            # ═══════════════════════════════════════════════════════════════
            # PHASE 2: Sequential cross-layer scanning (saves memory vs parallel)
            # ═══════════════════════════════════════════════════════════════
            await self.send_event("SAST Agent", "sast", "working", "Running Semgrep OWASP Top-10…")
            sast_r = await asyncio.wait_for(
                asyncio.to_thread(SASTAgent(self.llm_config).run, scan_result),
                timeout=120,
            )
            sast_r = self._safe(sast_r, {"vulnerabilities": []})
            await self.send_event("SAST Agent", "sast", "done",
                f"Found {len(sast_r['vulnerabilities'])} code vulnerabilities", sast_r)
            gc.collect()

            await self.send_event("Dependency Agent", "dependency", "working", "Querying OSV.dev CVE database…")
            dep_r = await asyncio.wait_for(
                asyncio.to_thread(DependencyAgent(self.llm_config).run, scan_result),
                timeout=60,
            )
            dep_r = self._safe(dep_r, {"vulnerabilities": []})
            await self.send_event("Dependency Agent", "dependency", "done",
                f"Found {len(dep_r['vulnerabilities'])} CVE issues", dep_r)
            gc.collect()

            await self.send_event("Secrets Agent", "secrets", "working", "Scanning for hardcoded secrets…")
            sec_r = await asyncio.wait_for(
                asyncio.to_thread(SecretsAgent(self.llm_config).run, scan_result),
                timeout=60,
            )
            sec_r = self._safe(sec_r, {"vulnerabilities": []})
            await self.send_event("Secrets Agent", "secrets", "done",
                f"Found {len(sec_r['vulnerabilities'])} exposed secrets", sec_r)
            gc.collect()

            await self.send_event("API Agent", "api", "working", "Discovering API endpoints & auth gaps…")
            api_r = await asyncio.wait_for(
                asyncio.to_thread(APIAgent(self.llm_config).run, scan_result),
                timeout=60,
            )
            api_r = self._safe(api_r, {"vulnerabilities": []})
            await self.send_event("API Agent", "api", "done",
                f"Found {len(api_r['vulnerabilities'])} API issues", api_r)
            gc.collect()

            all_vulns = (
                sast_r.get("vulnerabilities", []) +
                dep_r.get("vulnerabilities",  []) +
                sec_r.get("vulnerabilities",  []) +
                api_r.get("vulnerabilities",  [])
            )
            all_findings = {"vulnerabilities": all_vulns, "scan_result": scan_result}

            # Persist raw findings to Neon DB
            for v in all_vulns:
                try:
                    await execute(
                        "INSERT INTO vulnerabilities "
                        "(id, session_id, title, file_path, severity, cvss_score, "
                        "owasp_category, layer) "
                        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING",
                        v.get("id"), self.session_id,
                        v.get("title", "")[:255],
                        v.get("file_path", "")[:500],
                        v.get("severity", "MEDIUM"),
                        float(v.get("cvss_score", 0)),
                        v.get("owasp_category", "")[:255],
                        v.get("layer", "code"),
                    )
                except Exception:
                    pass

            # ═══════════════════════════════════════════════════════════════
            # PHASE 3: Attack Chain Synthesis
            # ═══════════════════════════════════════════════════════════════
            await self.send_event(
                "Attack Chain Agent", "attack_chain", "thinking",
                "Correlating findings across all layers to discover attack chains…",
            )
            chain_result = await asyncio.wait_for(
                asyncio.to_thread(AttackChainAgent(self.llm_config).run, all_findings),
                timeout=90,
            )
            await self.send_event(
                "Attack Chain Agent", "attack_chain", "done",
                f"Discovered {len(chain_result.get('attack_chains', []))} multi-layer attack chains!",
                chain_result,
            )
            gc.collect()

            # ═══════════════════════════════════════════════════════════════
            # PHASE 4: PoC + Severity + Patch + Risk (parallel)
            # ═══════════════════════════════════════════════════════════════
            for name, atype, msg in [
                ("PoC Agent",      "poc",      "Writing working exploit scripts…"),
                ("Severity Agent", "severity", "Applying CVSS 3.1 scoring…"),
                ("Patch Agent",    "patch",    "Generating context-aware code fixes…"),
                ("Risk Agent",     "risk",     "Calculating business risk in USD…"),
            ]:
                await self.send_event(name, atype, "working", msg)

            poc_r, sev_r, patch_r, risk_r = await asyncio.gather(
                asyncio.wait_for(
                    asyncio.to_thread(PoCAgent(self.llm_config).run, all_findings),
                    timeout=90,
                ),
                asyncio.wait_for(
                    asyncio.to_thread(SeverityAgent(self.llm_config).run, all_findings),
                    timeout=60,
                ),
                asyncio.wait_for(
                    asyncio.to_thread(PatchAgent(self.llm_config).run, all_findings, scan_result),
                    timeout=90,
                ),
                asyncio.wait_for(
                    asyncio.to_thread(RiskAgent(self.llm_config).run, all_findings, chain_result),
                    timeout=60,
                ),
                return_exceptions=True,
            )

            poc_r   = self._safe(poc_r,   {"exploits": []})
            sev_r   = self._safe(sev_r,   {"scored_vulnerabilities": []})
            patch_r = self._safe(patch_r, {"patches": []})
            risk_r  = self._safe(risk_r,  {"total_risk_usd": 0, "roi_ratio": 0})

            await self.send_event("PoC Agent",      "poc",      "done",
                f"Generated {len(poc_r.get('exploits', []))} exploit scripts", poc_r)
            await self.send_event("Severity Agent", "severity", "done",
                f"Scored {len(sev_r.get('scored_vulnerabilities', []))} findings", sev_r)
            await self.send_event("Patch Agent",    "patch",    "done",
                f"Generated {len(patch_r.get('patches', []))} patches", patch_r)
            await self.send_event(
                "Risk Agent", "risk", "done",
                f"Total exposure: ${risk_r.get('total_risk_usd', 0):,.0f} | "
                f"ROI of fixing: {risk_r.get('roi_ratio', 0):,.0f}x",
                risk_r,
            )

            # ═══════════════════════════════════════════════════════════════
            # PHASE 5: Sandbox Exploit Validation
            # ═══════════════════════════════════════════════════════════════
            validation_r: dict = {"validation_results": [], "validated_count": 0, "verified_count": 0}
            try:
                await self.send_event(
                    "Validation Agent", "validation", "working",
                    "Validating top findings in ephemeral sandbox…",
                )
                validation_r = await asyncio.wait_for(
                    asyncio.to_thread(
                        ValidationAgent(self.llm_config).run,
                        all_findings, poc_r,
                    ),
                    timeout=120,
                )
                validation_r = self._safe(validation_r, {"validation_results": [], "validated_count": 0, "verified_count": 0})
                # Persist to DB
                for ev in validation_r.get("validation_results", []):
                    try:
                        await execute(
                            "INSERT INTO validation_results "
                            "(session_id, vuln_id, verdict, method, container_image, "
                            "command_executed, exit_code, stdout_excerpt, stderr_excerpt, "
                            "timeout_hit, duration_ms, notes) "
                            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) "
                            "ON CONFLICT DO NOTHING",
                            self.session_id,
                            ev.get("vuln_id", ""),
                            ev.get("verdict", "SKIPPED"),
                            ev.get("method", ""),
                            ev.get("container_image", ""),
                            ev.get("command_executed", ""),
                            ev.get("exit_code"),
                            ev.get("stdout_excerpt", ""),
                            ev.get("stderr_excerpt", ""),
                            bool(ev.get("timeout_hit", False)),
                            int(ev.get("duration_ms", 0)),
                            ev.get("notes", ""),
                        )
                    except Exception:
                        pass
                await self.send_event(
                    "Validation Agent", "validation", "done",
                    f"Validated {validation_r.get('validated_count', 0)} findings — "
                    f"{validation_r.get('verified_count', 0)} confirmed exploitable.",
                    validation_r,
                )
            except Exception as ve:
                await self.send_event(
                    "Validation Agent", "validation", "error",
                    f"Validation phase skipped: {str(ve)[:120]}",
                )
            gc.collect()

            # ═══════════════════════════════════════════════════════════════
            # PHASE 6: Compliance Mapping
            # ═══════════════════════════════════════════════════════════════
            compliance_r: dict = {"compliance_mappings": [], "blast_radius": {}, "top_frameworks": [], "plain_language_summary": ""}
            try:
                await self.send_event(
                    "Compliance Agent", "compliance", "working",
                    "Mapping findings to SOC 2, HIPAA, PCI-DSS, GDPR, MITRE…",
                )
                compliance_r = await asyncio.wait_for(
                    asyncio.to_thread(
                        ComplianceAgent(self.llm_config).run,
                        all_findings,
                    ),
                    timeout=90,
                )
                compliance_r = self._safe(compliance_r, {"compliance_mappings": [], "blast_radius": {}, "top_frameworks": [], "plain_language_summary": ""})
                # Persist mappings to DB
                for m in compliance_r.get("compliance_mappings", []):
                    try:
                        await execute(
                            "INSERT INTO compliance_mappings "
                            "(session_id, vuln_id, framework, control_id, control_name, "
                            "owasp_category, rationale) "
                            "VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING",
                            self.session_id,
                            m.get("vuln_id", ""),
                            m.get("framework", ""),
                            m.get("control_id", ""),
                            m.get("control_name", ""),
                            m.get("owasp_category", ""),
                            m.get("rationale", ""),
                        )
                    except Exception:
                        pass
                fws = ", ".join(compliance_r.get("top_frameworks", [])[:3])
                await self.send_event(
                    "Compliance Agent", "compliance", "done",
                    f"Mapped {len(compliance_r.get('compliance_mappings', []))} controls. Top impact: {fws}",
                    compliance_r,
                )
            except Exception as ce:
                await self.send_event(
                    "Compliance Agent", "compliance", "error",
                    f"Compliance mapping skipped: {str(ce)[:120]}",
                )
            gc.collect()

            # ═══════════════════════════════════════════════════════════════
            # PHASE 7: Report
            # ═══════════════════════════════════════════════════════════════
            await self.send_event(
                "Report Agent", "report", "thinking",
                "Synthesising full pentest report with validation & compliance data…",
            )
            report_data = await asyncio.wait_for(
                asyncio.to_thread(
                    ReportAgent(self.llm_config).run,
                    github_url, scan_result, all_findings,
                    chain_result, poc_r, sev_r, patch_r, risk_r,
                ),
                timeout=120,
            )
            # Inject validation + compliance into report_data for PDF generation
            report_data["validation_results"]      = validation_r.get("validation_results", [])
            report_data["compliance_mappings"]      = compliance_r.get("compliance_mappings", [])
            report_data["compliance_blast_radius"]  = compliance_r.get("blast_radius", {})
            report_data["plain_language_summary"]   = compliance_r.get("plain_language_summary", "")
            generate_pdf_report(self.session_id, report_data)

            # Update Neon DB with final stats
            try:
                await execute(
                    "UPDATE audit_sessions SET "
                    "total_vulnerabilities=$1, critical_count=$2, high_count=$3, "
                    "medium_count=$4, low_count=$5, total_risk_usd=$6, "
                    "tech_stack=$7, file_count=$8, report_path=$9, repo_name=$10 "
                    "WHERE id=$11",
                    len(all_vulns),
                    risk_r.get("critical_count", 0),
                    risk_r.get("high_count",     0),
                    risk_r.get("medium_count",   0),
                    risk_r.get("low_count",      0),
                    float(risk_r.get("total_risk_usd", 0)),
                    json.dumps(scan_result.get("tech_stack", [])),
                    scan_result.get("file_count", 0),
                    f"/tmp/reports/{self.session_id}_report.pdf",
                    scan_result.get("repo_name", ""),
                    self.session_id,
                )
            except Exception:
                pass

            await self.send_event(
                "Report Agent", "report", "done",
                "✅ Audit complete! Pentest report ready for download.",
                {
                    "pdf_ready":      True,
                    "session_id":     self.session_id,
                    "total_risk_usd": risk_r.get("total_risk_usd", 0),
                    "total_vulns":    len(all_vulns),
                },
            )

            # ═══════════════════════════════════════════════════════════════
            # PHASE 8 (PR mode only): GitHub Guardian
            # ═══════════════════════════════════════════════════════════════
            if self.pr_mode and self.github_token and self.repo_full_name:
                try:
                    from integrations.github_guardian import (
                        create_or_update_check_run,
                        post_pr_security_comment,
                    )
                    await self.send_event(
                        "GitHub Guardian", "github_guardian", "working",
                        "Posting security summary to GitHub PR…",
                    )
                    comment_result = await asyncio.to_thread(
                        post_pr_security_comment,
                        self.github_token,
                        self.repo_full_name,
                        self.pr_number or 0,
                        self.session_id,
                        all_vulns,
                        validation_r.get("validation_results", []),
                        compliance_r.get("compliance_mappings", []),
                        risk_r,
                    )
                    check_result: dict = {}
                    if self.pr_sha:
                        check_result = await asyncio.to_thread(
                            create_or_update_check_run,
                            self.github_token,
                            self.repo_full_name,
                            self.pr_sha,
                            self.session_id,
                            all_vulns,
                            validation_r.get("validation_results", []),
                        )
                    # Log to DB
                    try:
                        await execute(
                            "INSERT INTO github_actions_log "
                            "(session_id, event_type, repo_full_name, pr_number, "
                            "sha, conclusion, comment_url, check_run_url, error_message) "
                            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
                            self.session_id, "pr_scan",
                            self.repo_full_name, self.pr_number, self.pr_sha,
                            check_result.get("conclusion", ""),
                            comment_result.get("comment_url", ""),
                            check_result.get("check_run_url", ""),
                            comment_result.get("error", "") or check_result.get("error", ""),
                        )
                        await execute(
                            "UPDATE audit_sessions SET pr_status=$1 WHERE id=$2",
                            check_result.get("conclusion", "commented"),
                            self.session_id,
                        )
                    except Exception:
                        pass

                    await self.send_event(
                        "GitHub Guardian", "github_guardian", "done",
                        f"PR comment posted. Check Run: {check_result.get('conclusion', 'n/a')}",
                        {
                            "comment_url":   comment_result.get("comment_url", ""),
                            "check_run_url": check_result.get("check_run_url", ""),
                            "conclusion":    check_result.get("conclusion", ""),
                        },
                    )
                except Exception as ge:
                    await self.send_event(
                        "GitHub Guardian", "github_guardian", "error",
                        f"GitHub Guardian failed (non-fatal): {str(ge)[:200]}",
                    )

        except asyncio.TimeoutError:
            await self.send_event(
                "System", "system", "error",
                "Audit timed out. Repository may be too large. Try a smaller repo.",
            )
        except Exception as exc:
            await self.send_event("System", "system", "error", f"Audit failed: {str(exc)}")
            raise
        finally:
            # Cleanup cloned repo to free disk space
            if clone_path and os.path.exists(clone_path):
                try:
                    shutil.rmtree(clone_path, ignore_errors=True)
                except Exception:
                    pass
