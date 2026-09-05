"""
Report Agent — Phase 5 (sequential).
Synthesises all findings into structured report sections using an LLM.
"""
import autogen
import json
from typing import Dict, Any


class ReportAgent:
    def __init__(self, llm_config: dict):
        self.llm_config = llm_config

    def run(
        self,
        github_url: str,
        scan_result: dict,
        all_findings: dict,
        chain_result: dict,
        poc_result: dict,
        severity_result: dict,
        patch_result: dict,
        risk_result: dict,
    ) -> Dict[str, Any]:

        vulns  = severity_result.get("scored_vulnerabilities") or all_findings.get("vulnerabilities", [])
        chains = chain_result.get("attack_chains", [])
        risk   = risk_result
        sc     = scan_result

        total_risk   = float(risk.get("total_risk_usd", 0))
        critical_cnt = risk.get("critical_count", 0)
        high_cnt     = risk.get("high_count", 0)
        file_count   = sc.get("file_count", 0)
        tech_stack   = ", ".join(sc.get("tech_stack", []))
        repo_name    = sc.get("repo_name", github_url)

        # Build context for LLM
        summary_ctx = {
            "repo":           repo_name,
            "tech_stack":     tech_stack,
            "file_count":     file_count,
            "total_vulns":    len(vulns),
            "critical":       critical_cnt,
            "high":           high_cnt,
            "medium":         risk.get("medium_count", 0),
            "low":            risk.get("low_count", 0),
            "total_risk_usd": total_risk,
            "roi_ratio":      risk.get("roi_ratio", 0),
            "attack_chains":  len(chains),
            "fix_hours":      risk.get("fix_investment_hours", 0),
        }

        try:
            agent = autogen.AssistantAgent(
                name="ReportAgent",
                llm_config=self.llm_config,
                system_message=(
                    "You are a professional penetration testing report writer. "
                    "Write clear, concise, executive-friendly security report sections. "
                    "Be specific about dollar amounts and business impact. "
                    "Output valid JSON only. No markdown fences."
                ),
            )
            proxy = autogen.UserProxyAgent(
                name="user_proxy",
                human_input_mode="NEVER",
                max_consecutive_auto_reply=1,
                code_execution_config=False,
            )
            prompt = (
                f"Write a professional pentest report for:\n{json.dumps(summary_ctx, indent=2)}\n\n"
                "Output JSON with these exact keys:\n"
                "{\n"
                '  "executive_summary": "3-sentence summary with dollar amounts",\n'
                '  "risk_overview": "2-3 sentence risk context",\n'
                '  "attack_chain_analysis": "2-3 sentence explanation of chained attack paths",\n'
                '  "remediation_intro": "1-2 sentence remediation priority guidance",\n'
                '  "conclusion": "2-3 sentence conclusion with ROI of fixing"\n'
                "}"
            )
            proxy.initiate_chat(agent, message=prompt, max_turns=1)
            resp = (agent.last_message(proxy) or {}).get("content", "{}")
            start = resp.find("{")
            end   = resp.rfind("}") + 1
            sections: dict = {}
            if start >= 0:
                sections = json.loads(resp[start:end])
        except Exception:
            sections = {}

        # Fallback content if LLM fails
        exec_summary = sections.get(
            "executive_summary",
            f"This security assessment of {repo_name} ({tech_stack}) identified {len(vulns)} "
            f"vulnerabilities across {file_count} files, including {critical_cnt} critical and "
            f"{high_cnt} high severity findings. "
            f"The estimated breach exposure totals ${total_risk:,.0f} including regulatory fines. "
            f"Immediate remediation of critical findings is strongly recommended.",
        )
        risk_overview = sections.get(
            "risk_overview",
            f"The repository contains {critical_cnt} critical, {high_cnt} high, "
            f"{risk.get('medium_count',0)} medium, and {risk.get('low_count',0)} low severity "
            f"vulnerabilities. The total estimated business risk is ${total_risk:,.0f}.",
        )
        chain_analysis = sections.get(
            "attack_chain_analysis",
            f"Analysis identified {len(chains)} multi-layer attack chain(s) where individual "
            "vulnerabilities can be combined to achieve greater impact than any single finding. "
            "These chains represent the highest priority remediation targets.",
        )
        remediation_intro = sections.get(
            "remediation_intro",
            f"Prioritise critical and high findings for immediate remediation within 24 hours. "
            f"The estimated fix investment is {risk.get('fix_investment_hours',0):.0f} engineer-hours, "
            f"representing a {risk.get('roi_ratio',0):.0f}x ROI compared to breach costs.",
        )
        conclusion = sections.get(
            "conclusion",
            f"Addressing all identified vulnerabilities will reduce breach exposure by an estimated "
            f"${total_risk:,.0f}. The recommended remediation investment of approximately "
            f"{risk.get('fix_investment_hours',0):.0f} engineer-hours yields a "
            f"{risk.get('roi_ratio',0):.0f}x return on security investment.",
        )

        return {
            "executive_summary":    exec_summary,
            "risk_overview":        risk_overview,
            "attack_chain_analysis": chain_analysis,
            "remediation_intro":    remediation_intro,
            "conclusion":           conclusion,
            "vulnerabilities":      vulns,
            "attack_chains":        chains,
            "exploits":             poc_result.get("exploits", []),
            "patches":              patch_result.get("patches", []),
            "risk":                 risk,
            "scan_result":          scan_result,
        }
