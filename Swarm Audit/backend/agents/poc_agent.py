"""
PoC Agent — Phase 4 (parallel).
Generates working proof-of-concept exploit scripts for identified vulnerabilities.
"""
import autogen
import json
from typing import Dict, Any


class PoCAgent:
    def __init__(self, llm_config: dict):
        self.llm_config = llm_config

    def run(self, all_findings: dict) -> Dict[str, Any]:
        vulns = all_findings.get("vulnerabilities", [])
        if not vulns:
            return {"exploits": []}

        # Select top 8 by CVSS score
        top_vulns = sorted(vulns, key=lambda v: float(v.get("cvss_score", 0)), reverse=True)[:8]

        agent = autogen.AssistantAgent(
            name="PoCAgent",
            llm_config=self.llm_config,
            system_message=(
                "You are an expert penetration tester. "
                "For each vulnerability provided, write a MINIMAL working proof-of-concept exploit. "
                "Use Python or curl. Keep each script under 50 lines. "
                "Include: setup comments, the exploit steps, and expected output. "
                "Output JSON array: [{vuln_id, poc_code, language, description}]. "
                "No markdown fences. Real working code only."
            ),
        )
        proxy = autogen.UserProxyAgent(
            name="user_proxy",
            human_input_mode="NEVER",
            max_consecutive_auto_reply=1,
            code_execution_config=False,
        )

        vuln_summaries = json.dumps(
            [
                {
                    "id":             v.get("id"),
                    "title":          v.get("title"),
                    "description":    v.get("description", "")[:200],
                    "file_path":      v.get("file_path", ""),
                    "layer":          v.get("layer", "code"),
                    "owasp_category": v.get("owasp_category", ""),
                    "cvss_score":     v.get("cvss_score", 0),
                }
                for v in top_vulns
            ],
            indent=2,
        )

        prompt = (
            f"Write minimal PoC exploit scripts for these vulnerabilities:\n{vuln_summaries}\n"
            "Output JSON array: "
            '[{"vuln_id": "...", "poc_code": "#!/usr/bin/env python3\\n...", '
            '"language": "python", "description": "What this PoC demonstrates"}]'
        )

        proxy.initiate_chat(agent, message=prompt, max_turns=1)
        response = (agent.last_message(proxy) or {}).get("content", "[]")

        exploits = []
        try:
            start = response.find("[")
            end   = response.rfind("]") + 1
            if start >= 0:
                exploits = json.loads(response[start:end])
        except Exception:
            pass

        # Fallback: generate template PoCs if LLM fails
        if not exploits:
            for v in top_vulns[:3]:
                layer = v.get("layer", "code")
                if layer == "dependency":
                    poc = (
                        "#!/usr/bin/env python3\n"
                        f"# PoC: {v.get('title','Vulnerability')}\n"
                        "# Demonstrates exploiting a known vulnerable dependency\n"
                        "import requests\n"
                        "target = 'http://TARGET_HOST'\n"
                        "# Trigger the vulnerable code path\n"
                        "resp = requests.get(f'{target}/vulnerable-endpoint')\n"
                        "print(f'Status: {resp.status_code}')\n"
                        "print(f'Response: {resp.text[:200]}')\n"
                    )
                elif layer == "secret":
                    poc = (
                        "#!/usr/bin/env python3\n"
                        f"# PoC: {v.get('title','Exposed Secret')}\n"
                        "# Demonstrates using an exposed credential\n"
                        "import os\n"
                        "# Credential found in repository — use for authentication\n"
                        "# EXPOSED_KEY = '<key found in repo>'\n"
                        "print('Credential exposed — rotate immediately.')\n"
                    )
                elif layer == "api":
                    poc = (
                        "#!/bin/bash\n"
                        f"# PoC: {v.get('title','Unprotected Endpoint')}\n"
                        "# Demonstrates unauthenticated access to sensitive endpoint\n"
                        "TARGET='http://TARGET_HOST'\n"
                        f"curl -s -X GET \"$TARGET{v.get('endpoint', '/api/admin')}\" \\\n"
                        "  -H 'Content-Type: application/json'\n"
                        "echo ''\n"
                        "# Expected: sensitive data returned without authentication\n"
                    )
                else:
                    poc = (
                        "#!/usr/bin/env python3\n"
                        f"# PoC: {v.get('title','Code Vulnerability')}\n"
                        "# Demonstrates exploitation of code-level vulnerability\n"
                        "import requests\n"
                        "target = 'http://TARGET_HOST'\n"
                        "payload = \"'; DROP TABLE users; --\"\n"
                        "resp = requests.post(f'{target}/api/data', json={'input': payload})\n"
                        "print(f'Status: {resp.status_code}')\n"
                    )
                exploits.append({
                    "vuln_id":     v.get("id"),
                    "poc_code":    poc,
                    "language":    "bash" if layer == "api" else "python",
                    "description": f"PoC for {v.get('title', 'vulnerability')}",
                })

        return {"exploits": exploits}
