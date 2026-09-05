# 🔐 SwarmAudit — Autonomous Security Audit Swarm

[![Backend CI/CD](https://github.com/yourusername/swarmaudit/actions/workflows/backend-ci-cd.yml/badge.svg)](https://github.com/yourusername/swarmaudit/actions)
[![Frontend CI/CD](https://github.com/yourusername/swarmaudit/actions/workflows/frontend-ci-cd.yml/badge.svg)](https://github.com/yourusername/swarmaudit/actions)
![Python](https://img.shields.io/badge/python-3.11-blue)
![Next.js](https://img.shields.io/badge/next.js-14-black)
![License](https://img.shields.io/badge/license-MIT-green)

> Paste a GitHub repo URL → 9 AI agents run a full penetration test → PDF report in ~4 minutes. **Free.**

---

## ⚡ What Makes SwarmAudit Different

Every existing tool (Snyk, Semgrep, GitHub Copilot Autofix) finds **isolated** vulnerabilities.
**SwarmAudit's Attack Chain Agent does something no other tool does:**
it correlates findings across code, dependencies, secrets, and APIs into complete exploit paths.

```
lodash CVE (dependency)
  → prototype pollution bypasses auth middleware (code)
  → reaches unprotected SQL query (code)
  → full database read
  → credential extraction → account takeover
```

This cross-layer synthesis produces a CVSS score higher than any single finding and
shows engineers which patch **breaks the entire chain**, not just one link.

---

## 🤖 Agent Architecture

```mermaid
flowchart TD
    A[User: GitHub URL] --> B[Scanner Agent\nClone + map repo]

    B --> C[SAST Agent\nOWASP Top 10]
    B --> D[Dependency Agent\nCVE check OSV.dev]
    B --> E[Secrets Agent\nHardcoded creds]
    B --> F[API Agent\nAuth gap detection]

    C & D & E & F --> G[Attack Chain Agent\n★ CORE INNOVATION\nCross-layer synthesis]

    G --> H[PoC Agent\nExploit scripts]
    G --> I[Severity Agent\nCVSS 3.1 scoring]
    G --> J[Patch Agent\nCode fixes]
    G --> K[Risk Agent\nUSD business risk]

    H & I & J & K --> L[Report Agent\nPDF pentest report]
    L --> M[User: PDF Report]

    style G fill:#c0392b,color:#fff
    style A fill:#0f3460,color:#fff
    style M fill:#27ae60,color:#fff
```

---

## 🆓 Completely Free Stack

| Component          | Tool                       | Cost           |
|--------------------|----------------------------|----------------|
| LLM                | Groq (Llama 3.1 70B)       | Free           |
| Agent Framework    | Microsoft AutoGen          | Free (OSS)     |
| SAST Scanner       | Semgrep OSS                | Free (OSS)     |
| CVE Database       | OSV.dev API                | Free           |
| Database           | Neon.tech PostgreSQL       | Free tier      |
| Backend Host       | Render.com                 | Free tier      |
| Frontend Host      | Vercel                     | Free tier      |
| Container Registry | Docker Hub                 | Free (public)  |
| CI/CD              | GitHub Actions             | Free (public)  |
| PDF Generation     | ReportLab                  | Free (OSS)     |

---

## 🚀 Quick Start (Local)

### Prerequisites
- Docker & Docker Compose
- Node.js 20+
- Git

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/swarmaudit
cd swarmaudit
```

### 2. Configure backend environment

```bash
cp backend/.env.example backend/.env
# Edit backend/.env — add your GROQ_API_KEY and DATABASE_URL
```

Get your free keys:
- **Groq API key**: [console.groq.com](https://console.groq.com) → API Keys → Create
- **Database URL**: [neon.tech](https://neon.tech) → New Project → Connection string

### 3. Start backend + nginx

```bash
docker-compose up --build
# Backend runs at http://localhost:8000
# Nginx proxy at http://localhost:80
```

### 4. Start frontend (separate terminal)

```bash
cd frontend
cp .env.example .env.local
# Edit .env.local:
#   NEXT_PUBLIC_API_URL=http://localhost:8000
#   NEXT_PUBLIC_WS_URL=ws://localhost:8000
npm install
npm run dev
```

### 5. Open the app

```
http://localhost:3000
```

Paste a public GitHub URL and click **Start Audit →**

---

## 🌐 Production Deployment

### Step 1: Database — Neon.tech (Free)

1. Go to [neon.tech](https://neon.tech) → Sign up (no credit card)
2. New Project → Name: `swarmaudit`
3. Dashboard → Connection Details → Copy connection string
   ```
   postgresql://user:pass@ep-xxx.us-east-2.aws.neon.tech/neondb?sslmode=require
   ```
4. Tables are auto-created on first backend startup

### Step 2: Backend — Render.com (Free)

1. [render.com](https://render.com) → New → Web Service
2. Connect your GitHub repo
3. Settings:
   - **Root Directory**: `backend`
   - **Runtime**: Docker
   - **Instance Type**: Free
4. Environment Variables (set all from `backend/.env.example`)
5. Health Check Path: `/health`
6. Your backend URL: `https://swarmaudit-backend.onrender.com`

**Alternative: Railway.app**
```bash
# Install Railway CLI
npm install -g @railway/cli
railway login
cd backend && railway up
```

### Step 3: Frontend — Vercel (Free)

1. [vercel.com](https://vercel.com) → New Project → Import GitHub repo
2. Root Directory: `frontend`
3. Framework: Next.js (auto-detected)
4. Environment Variables:
   ```
   NEXT_PUBLIC_API_URL = https://swarmaudit-backend.onrender.com
   NEXT_PUBLIC_WS_URL  = wss://swarmaudit-backend.onrender.com
   ```
5. Deploy — auto-deploys on every push to `main`

### Step 4: Docker Hub (CI/CD image registry)

1. [hub.docker.com](https://hub.docker.com) → Create Account
2. New Repository: `swarmaudit-backend` (public)
3. Account Settings → Security → New Access Token → copy token

---

## 🔑 GitHub Actions Secrets

Go to: **GitHub Repo → Settings → Secrets and variables → Actions**

| Secret                | Value                                              | Used by        |
|-----------------------|----------------------------------------------------|----------------|
| `DOCKERHUB_USERNAME`  | Your Docker Hub username                           | Backend CI/CD  |
| `DOCKERHUB_TOKEN`     | Docker Hub access token                            | Backend CI/CD  |
| `RENDER_API_KEY`      | Render.com API key (Dashboard → Account → API)     | Backend CI/CD  |
| `RENDER_SERVICE_ID`   | From Render service URL                            | Backend CI/CD  |
| `VERCEL_TOKEN`        | Vercel Settings → Tokens → Create                  | Frontend CI/CD |
| `VERCEL_ORG_ID`       | Vercel Settings → General → Your ID               | Frontend CI/CD |
| `VERCEL_PROJECT_ID`   | Vercel Project → Settings → General               | Frontend CI/CD |
| `GROQ_API_KEY`        | console.groq.com → API Keys                        | Backend (env)  |
| `DATABASE_URL`        | Neon.tech connection string                        | Backend (env)  |

---

## 🏗️ Architecture Deep-Dive

### Phase 1 — Scanner Agent
Clones the target repository (shallow, depth=1) using GitPython. Maps the file tree,
detects technology stack from file extensions and framework signal files, and identifies
manifest files for dependency scanning.

### Phase 2 — Parallel Cross-Layer Scanning (4 agents)
- **SAST Agent**: Runs Semgrep with OWASP Top 10, SQL injection, XSS, and secrets rulesets.
  Falls back to custom regex patterns for common secret types.
- **Dependency Agent**: Parses `requirements.txt`, `package.json`, `go.mod`, `Cargo.toml`,
  `Gemfile`, `pom.xml`, and queries the OSV.dev API (free, no API key) for CVEs.
- **Secrets Agent**: Walks all text files with 15 regex patterns for passwords, API keys,
  AWS credentials, GitHub tokens, Stripe keys, private keys, and database URLs.
  Uses LLM to filter false positives (test data, placeholders).
- **API Agent**: Detects routes across Flask, FastAPI, Django, Express, Spring MVC,
  and Next.js. Flags sensitive endpoints (admin, user, payment) lacking auth decorators.

### Phase 3 — Attack Chain Agent (CORE INNOVATION ★)
Feeds all Phase 2 findings into Llama 3.1 70B with a carefully engineered prompt that asks
the model to synthesise cross-layer exploit paths. The model receives a layer breakdown and
top findings, and produces ordered attack chains with CVSS scores, business impact in USD,
and recommended fix sequences that break the chain most efficiently.

### Phase 4 — Parallel Enrichment (4 agents)
- **PoC Agent**: Writes minimal working exploit scripts (Python/curl) for top 8 findings
- **Severity Agent**: Applies CVSS 3.1 base scores using a keyword lookup table + raw severity
- **Patch Agent**: Reads actual source context (±10 lines) and generates unified diffs
- **Risk Agent**: IBM 2024 breach formula ($165/record) + GDPR/CCPA regulatory fines

### Phase 5 — Report Agent
LLM writes executive summary, risk overview, attack chain analysis, and conclusion.
ReportLab generates a professional PDF with dark branding, colour-coded severity tables,
attack chain diagrams, PoC exploits, and patches.

---

## 📁 Project Structure

```
swarmaudit/
├── backend/
│   ├── main.py                        ← FastAPI app + WebSocket
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── models/schemas.py              ← Pydantic models
│   ├── database/
│   │   ├── connection.py              ← Neon.tech asyncpg pool
│   │   └── migrations.py             ← CREATE TABLE IF NOT EXISTS
│   ├── agents/                        ← 11 specialised agents
│   │   ├── scanner_agent.py
│   │   ├── sast_agent.py
│   │   ├── dependency_agent.py
│   │   ├── secrets_agent.py
│   │   ├── api_agent.py
│   │   ├── attack_chain_agent.py      ← ★ Core innovation
│   │   ├── poc_agent.py
│   │   ├── severity_agent.py
│   │   ├── patch_agent.py
│   │   ├── risk_agent.py
│   │   └── report_agent.py
│   ├── orchestrator/
│   │   └── swarm_orchestrator.py      ← 5-phase async orchestration
│   └── tools/
│       ├── github_tools.py
│       ├── semgrep_tools.py
│       └── report_generator.py        ← ReportLab PDF
├── frontend/
│   ├── app/
│   │   ├── page.tsx                   ← Landing page
│   │   ├── layout.tsx
│   │   └── audit/[sessionId]/page.tsx ← Live 3-column dashboard
│   ├── components/
│   │   ├── AgentCard.tsx
│   │   ├── AuditForm.tsx
│   │   ├── LiveTerminal.tsx
│   │   ├── VulnerabilityCard.tsx
│   │   ├── AttackChainGraph.tsx       ← Mermaid diagrams
│   │   ├── RiskDashboard.tsx
│   │   ├── ReportViewer.tsx
│   │   └── SeverityBadge.tsx
│   └── lib/
│       ├── websocket.ts               ← WS manager with auto-reconnect
│       └── api.ts                     ← Typed API client
├── .github/workflows/
│   ├── backend-ci-cd.yml              ← Docker Hub + Render deploy
│   └── frontend-ci-cd.yml             ← Vercel deploy
├── docker-compose.yml                 ← Local dev
├── nginx.conf                         ← WebSocket-aware reverse proxy
└── README.md
```

---

## ⚠️ Security & Legal

- **For authorized security testing only.** Only scan repositories you own or have explicit written permission to test.
- No credentials are ever stored. All secrets are passed via environment variables.
- The tool generates PoC exploits for educational purposes. Never use against production systems without authorization.
- Findings are stored in your own Neon.tech database — no data leaves your infrastructure.

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.
