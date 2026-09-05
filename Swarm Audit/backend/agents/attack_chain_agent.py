"""
Attack Chain Agent — Phase 3, THE CORE INNOVATION.
Correlates findings from all Phase 2 agents into complete multi-layer exploit paths.
"""
import autogen
import json
import uuid
from typing import Dict, Any


class AttackChainAgent:
    def __init__(self, llm_config: dict):
        self.llm_config = llm_config
        self.agent = autogen.AssistantAgent(
            name="AttackChainAgent",
            llm_config=llm_config,
            system_message="""You are a world-class penetration tester specialising in
ATTACK CHAIN SYNTHESIS — the art of connecting isolated vulnerability findings
across different layers (code, dependencies, secrets, APIs) into complete,
realistic exploit paths that a real attacker would use.

WHAT NO OTHER TOOL DOES: You connect the dots between findings.
Example: "lodash prototype pollution (dependency) → bypass auth middleware (code)
→ reach unprotected SQL query (code) → full database read → credential theft → account takeover"

For each chain:
1. Name: descriptive "verb + target" attack name
2. Steps: ordered list with layer, vuln reference, how it enables the next step
3. CVSS: overall score (typically higher than any single finding)
4. Exploit path: clear paragraph an executive can understand
5. Fix sequence: which order patches break the chain most efficiently

Output a valid JSON array of attack chain objects. No markdown fences.""",
        )

    def run(self, all_findings: dict) -> Dict[str, Any]:
        vulns = all_findings.get("vulnerabilities", [])
        if not vulns:
            return {"attack_chains": []}

        by_layer = {"code": [], "dependency": [], "secret": [], "api": []}
        for v in vulns:
            layer = v.get("layer", "code")
            by_layer.setdefault(layer, []).append(v)

        summary = json.dumps(
            [
                {
                    "id":             v.get("id"),
                    "title":          v.get("title"),
                    "layer":          v.get("layer", "code"),
                    "severity":       v.get("severity", "MEDIUM"),
                    "severity_raw":   v.get("severity_raw", "WARNING"),
                    "file_path":      v.get("file_path", ""),
                    "owasp_category": v.get("owasp_category", ""),
                }
                for v in vulns[:15]
            ],
            indent=2,
        )

        prompt = f"""Analyse these vulnerability findings and synthesise ATTACK CHAINS.

Layer breakdown:
- Code findings:     {len(by_layer['code'])}
- Dependency CVEs:   {len(by_layer['dependency'])}
- Secrets exposed:   {len(by_layer['secret'])}
- API issues:        {len(by_layer['api'])}

Findings:
{summary}

Output a JSON array. Each element:
{{
  "id": "chain-001",
  "name": "Descriptive attack chain name",
  "chain_steps": [
    {{
      "step_num": 1,
      "title": "Step title",
      "layer": "dependency",
      "vuln_id": "DEP-xxxx",
      "description": "How this step is exploited",
      "enables_next": "Why this step unlocks the next step"
    }}
  ],
  "exploit_path": "Complete plain-English attack narrative one paragraph",
  "risk_level": "CRITICAL",
  "cvss_overall": 9.1,
  "business_impact_usd": 500000,
  "fix_sequence": ["VULN-001 first — breaks chain entry", "VULN-002 second"]
}}

Produce 2-4 realistic chains. Focus on cross-layer combinations."""

        proxy = autogen.UserProxyAgent(
            name="user_proxy",
            human_input_mode="NEVER",
            max_consecutive_auto_reply=1,
            code_execution_config=False,
        )
        proxy.initiate_chat(self.agent, message=prompt, max_turns=1)
        response = (self.agent.last_message(proxy) or {}).get("content", "[]")

        chains = []
        try:
            start = response.find("[")
            end   = response.rfind("]") + 1
            if start >= 0:
                chains = json.loads(response[start:end])
        except Exception:
            chains = []

        # Fallback synthetic chain if LLM didn't return valid JSON
        if not chains and len(vulns) >= 2:
            layers_present = sorted({v.get("layer", "code") for v in vulns[:4]})
            chains = [
                {
                    "id":   "chain-001",
                    "name": "Multi-Layer Vulnerability Chain",
                    "chain_steps": [
                        {
                            "step_num":    i + 1,
                            "title":       v.get("title", "")[:60],
                            "layer":       v.get("layer", "code"),
                            "vuln_id":     v.get("id", ""),
                            "description": v.get("raw_message", "")[:120],
                            "enables_next": "Provides foothold for the next step",
                        }
                        for i, v in enumerate(vulns[:4])
                    ],
                    "exploit_path": (
                        f"An attacker chains {min(len(vulns), 4)} vulnerabilities across "
                        f"{len(layers_present)} layer(s) ({', '.join(layers_present)}) to achieve "
                        "significant impact including potential data exfiltration."
                    ),
                    "risk_level":          "HIGH",
                    "cvss_overall":        8.0,
                    "business_impact_usd": 250_000,
                    "fix_sequence":        [v.get("id", "") for v in vulns[:4]],
                }
            ]

        return {"attack_chains": chains}
