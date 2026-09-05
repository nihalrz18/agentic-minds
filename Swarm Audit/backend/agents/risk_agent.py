"""
Risk Agent — Phase 4 (parallel).
Calculates business risk in USD using IBM breach formula and regulatory fine estimates.
"""
import autogen
import json
from typing import Dict, Any


class RiskAgent:
    def __init__(self, llm_config: dict):
        self.llm_config = llm_config

    def run(self, all_findings: dict, chain_result: dict) -> Dict[str, Any]:
        vulns  = all_findings.get("vulnerabilities", [])
        chains = chain_result.get("attack_chains", [])

        # ── Count by severity ──────────────────────────────────────────────
        critical = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
        high     = sum(1 for v in vulns if v.get("severity") == "HIGH")
        medium   = sum(1 for v in vulns if v.get("severity") == "MEDIUM")
        low      = sum(1 for v in vulns if v.get("severity") in ("LOW", "INFO"))

        # ── IBM 2024 breach formula ────────────────────────────────────────
        # $4.88M avg cost (2024), scaled by affected records
        # $165/record average (IBM Cost of Data Breach Report 2024)
        breach_cost_per_record = 165.0
        # Estimate affected records: each critical/high vuln may expose more records
        affected_records = max(
            1000,
            critical * 50_000 + high * 10_000 + medium * 1_000,
        )
        technical_risk = affected_records * breach_cost_per_record

        # ── Regulatory fines ──────────────────────────────────────────────
        # GDPR Article 83: up to 4% of annual revenue or €20M (whichever higher)
        # Estimate for typical startup: $5M revenue → max $200K GDPR fine
        gdpr_fine = min(critical * 50_000 + high * 25_000, 20_000_000.0)
        # CCPA: $750 per consumer record for intentional violations
        ccpa_fine = min(affected_records * 750, 7_500_000.0)
        regulatory_fine = max(gdpr_fine, ccpa_fine)

        # ── Reputational damage ───────────────────────────────────────────
        # Typically 30-50% of direct breach cost (stock price drop, customer churn)
        reputational_cost = technical_risk * 0.40

        # ── Total ─────────────────────────────────────────────────────────
        total_risk = technical_risk + regulatory_fine + reputational_cost

        # Factor in attack chain business impacts
        for chain in chains:
            chain_usd = float(chain.get("business_impact_usd", 0))
            if chain_usd > total_risk:
                total_risk = chain_usd

        # ── Fix investment ─────────────────────────────────────────────────
        # Estimated engineering hours at $150/hr
        fix_hours   = critical * 8.0 + high * 4.0 + medium * 2.0 + low * 0.5
        fix_cost    = fix_hours * 150.0
        roi_ratio   = total_risk / max(fix_cost, 1.0)

        risk_breakdown = {
            "technical_breach":    round(technical_risk, 2),
            "regulatory_fines":    round(regulatory_fine, 2),
            "reputational_damage": round(reputational_cost, 2),
        }

        base_result: Dict[str, Any] = {
            "total_risk_usd":            round(total_risk, 2),
            "regulatory_fine_usd":       round(regulatory_fine, 2),
            "breach_cost_per_record_usd": breach_cost_per_record,
            "affected_records_est":      affected_records,
            "fix_investment_hours":      round(fix_hours, 1),
            "fix_cost_usd":              round(fix_cost, 2),
            "roi_ratio":                 round(roi_ratio, 1),
            "risk_breakdown":            risk_breakdown,
            "critical_count":            critical,
            "high_count":                high,
            "medium_count":              medium,
            "low_count":                 low,
        }

        # ── LLM enrichment ────────────────────────────────────────────────
        try:
            agent = autogen.AssistantAgent(
                name="RiskAgent",
                llm_config=self.llm_config,
                system_message=(
                    "You are a CISO and risk quantification expert. "
                    "Analyse vulnerability findings and validate business risk in USD. "
                    "Use IBM Cost of Data Breach Report 2024 methodology ($4.88M avg, $165/record). "
                    "Include GDPR / CCPA regulatory fine estimates. "
                    "Output valid JSON only. No markdown."
                ),
            )
            proxy = autogen.UserProxyAgent(
                name="user_proxy",
                human_input_mode="NEVER",
                max_consecutive_auto_reply=1,
                code_execution_config=False,
            )
            prompt = (
                f"Validate and enhance this risk calculation:\n"
                f"Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}\n"
                f"Estimated affected records: {affected_records}\n"
                f"Attack chains discovered: {len(chains)}\n"
                f"Current calculation:\n{json.dumps(base_result, indent=2)}\n\n"
                "Output JSON with same structure. Add a 'risk_narrative' field: "
                "2-sentence plain-English business explanation of the risk."
            )
            proxy.initiate_chat(agent, message=prompt, max_turns=1)
            resp = (agent.last_message(proxy) or {}).get("content", "{}")
            start = resp.find("{")
            end   = resp.rfind("}") + 1
            if start >= 0:
                enriched = json.loads(resp[start:end])
                for k, v in enriched.items():
                    if k == "total_risk_usd" and isinstance(v, (int, float)) and v > 0:
                        base_result[k] = round(float(v), 2)
                    elif k == "roi_ratio" and isinstance(v, (int, float)) and v > 0:
                        base_result[k] = round(float(v), 1)
                    elif k == "risk_narrative" and isinstance(v, str):
                        base_result[k] = v
                    elif k == "regulatory_fine_usd" and isinstance(v, (int, float)) and v > 0:
                        base_result[k] = round(float(v), 2)
        except Exception:
            pass

        if "risk_narrative" not in base_result:
            base_result["risk_narrative"] = (
                f"This repository has {len(vulns)} vulnerabilities with a total estimated breach "
                f"exposure of ${base_result['total_risk_usd']:,.0f} including regulatory fines of "
                f"${base_result['regulatory_fine_usd']:,.0f}. "
                f"Fixing all issues costs an estimated "
                f"{base_result['fix_investment_hours']:.0f} engineer-hours, "
                f"representing a {base_result['roi_ratio']:.0f}x return on investment."
            )

        return base_result
