"""
Compliance Agent — maps every vulnerability to SOC 2, HIPAA, PCI-DSS,
GDPR, and MITRE ATT&CK controls and enriches the rationale with the LLM.

Uses local embedded mapping data (no external API calls for mapping).
Uses Groq/Llama for optional auditor/developer summary enrichment.
"""
import json
import logging
import os
from typing import Any, Dict, List

import autogen  # type: ignore

from tools.compliance_mappings import (
    get_compliance_blast_radius,
    get_compliance_mappings,
    resolve_owasp_category,
)

logger = logging.getLogger("compliance_agent")


class ComplianceAgent:
    """Maps all findings to compliance frameworks and generates summaries."""

    def __init__(self, llm_config: Dict[str, Any]):
        self.llm_config = llm_config

    def run(self, all_findings: Dict[str, Any]) -> Dict[str, Any]:
        """
        Synchronous entry point (called via asyncio.to_thread).

        Returns:
            {
                compliance_mappings: List[ComplianceMapping dicts],
                blast_radius: Dict,
                top_frameworks: List[str],
                plain_language_summary: str,
            }
        """
        vulns = all_findings.get("vulnerabilities", [])
        if not vulns:
            return {
                "compliance_mappings":      [],
                "blast_radius":             {},
                "top_frameworks":           [],
                "plain_language_summary":   "No vulnerabilities found — no compliance impact detected.",
            }

        # ── Step 1: Generate static compliance mappings ───────────────────────
        all_mappings: List[Dict[str, Any]] = []
        for vuln in vulns:
            mappings = get_compliance_mappings(vuln)
            all_mappings.extend(mappings)

        # ── Step 2: Compute blast radius ──────────────────────────────────────
        blast_radius = get_compliance_blast_radius(all_mappings)

        top_frameworks = sorted(
            blast_radius.get("framework_counts", {}).items(),
            key=lambda x: x[1],
            reverse=True
        )
        top_fw_names = [fw for fw, _ in top_frameworks[:3]]

        # ── Step 3: LLM plain-language summary ────────────────────────────────
        plain_summary = self._generate_plain_summary(vulns, blast_radius, top_fw_names)

        return {
            "compliance_mappings":    all_mappings,
            "blast_radius":           blast_radius,
            "top_frameworks":         top_fw_names,
            "plain_language_summary": plain_summary,
        }

    def _generate_plain_summary(
        self,
        vulns: List[Dict[str, Any]],
        blast_radius: Dict[str, Any],
        top_frameworks: List[str],
    ) -> str:
        """Use LLM to generate a plain-English compliance risk summary."""
        try:
            crit  = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
            high  = sum(1 for v in vulns if v.get("severity") == "HIGH")
            total = len(vulns)
            fw_str = ", ".join(top_frameworks) if top_frameworks else "multiple frameworks"
            high_risk_controls = blast_radius.get("top_high_risk_controls", [])
            controls_str = "; ".join(
                f"{c['framework']} {c['control_id']}" for c in high_risk_controls[:4]
            )

            prompt = f"""You are a compliance officer writing a brief, plain-English risk summary
for a technical security audit report. Be concise (3-5 sentences max).

Audit findings:
- Total vulnerabilities: {total} ({crit} CRITICAL, {high} HIGH)
- Most impacted compliance frameworks: {fw_str}
- Top controls at risk: {controls_str}

Write a plain-language paragraph that:
1. Explains what compliance risk this creates for a non-technical executive
2. Names the key frameworks impacted
3. States the urgency of remediation
4. Avoids jargon

Do not include bullet points. Return only the paragraph text."""

            assistant = autogen.AssistantAgent(
                name="ComplianceSummariser",
                llm_config=self.llm_config,
                system_message="You are a compliance officer producing concise, accurate risk summaries.",
                max_consecutive_auto_reply=0,
            )
            user_proxy = autogen.UserProxyAgent(
                name="User",
                human_input_mode="NEVER",
                max_consecutive_auto_reply=0,
                code_execution_config=False,
            )
            user_proxy.initiate_chat(assistant, message=prompt, silent=True)
            last = user_proxy.last_message(assistant)
            if last and last.get("content"):
                return last["content"].strip()
        except Exception as e:
            logger.warning(f"LLM compliance summary failed: {e}")

        # Fallback static summary
        total  = len(vulns)
        crit   = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
        fw_str = ", ".join(top_frameworks) if top_frameworks else "SOC 2, GDPR, PCI-DSS"
        return (
            f"This audit identified {total} security vulnerabilities ({crit} critical) "
            f"that affect compliance with {fw_str}. "
            f"Unpatched vulnerabilities may result in regulatory fines, audit failures, "
            f"and data breach liability. Immediate remediation of critical and high findings "
            f"is strongly recommended before the next compliance review."
        )
