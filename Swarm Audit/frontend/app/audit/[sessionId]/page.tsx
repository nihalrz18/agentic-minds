'use client';

import { useEffect, useRef, useState, useCallback, Suspense } from 'react';
import { useParams, useSearchParams } from 'next/navigation';
import { ArrowLeft } from 'lucide-react';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';

import { WebSocketManager, AgentMessage } from '../../../lib/websocket';
import AgentCard from '../../../components/AgentCard';
import LiveTerminal, { TerminalLine } from '../../../components/LiveTerminal';
import VulnerabilityCard from '../../../components/VulnerabilityCard';
import AttackChainGraph from '../../../components/AttackChainGraph';
import RiskDashboard from '../../../components/RiskDashboard';
import ReportViewer from '../../../components/ReportViewer';
import { ValidationBadge } from '../../../components/ValidationBadge';
import { EvidencePanel } from '../../../components/EvidencePanel';
import { ComplianceMatrix } from '../../../components/ComplianceMatrix';
import { PRCommentPreview } from '../../../components/PRCommentPreview';

import type { ValidationEvidence, ComplianceMapping, BlastRadius } from '../../../lib/api';

// ─── Types ───────────────────────────────────────────────────────────────────
type AgentStatus = 'waiting' | 'thinking' | 'working' | 'done' | 'error';

interface AgentState {
  name:          string;
  type:          string;
  status:        AgentStatus;
  latestMessage: string;
  completedAt?:  number;
}

const INITIAL_AGENTS: Record<string, AgentState> = {
  scanner:        { name: 'Scanner Agent',      type: 'scanner',        status: 'waiting', latestMessage: '' },
  sast:           { name: 'SAST Agent',          type: 'sast',           status: 'waiting', latestMessage: '' },
  dependency:     { name: 'Dependency Agent',    type: 'dependency',     status: 'waiting', latestMessage: '' },
  secrets:        { name: 'Secrets Agent',       type: 'secrets',        status: 'waiting', latestMessage: '' },
  api:            { name: 'API Agent',           type: 'api',            status: 'waiting', latestMessage: '' },
  attack_chain:   { name: 'Attack Chain Agent',  type: 'attack_chain',   status: 'waiting', latestMessage: '' },
  poc:            { name: 'PoC Agent',           type: 'poc',            status: 'waiting', latestMessage: '' },
  severity:       { name: 'Severity Agent',      type: 'severity',       status: 'waiting', latestMessage: '' },
  patch:          { name: 'Patch Agent',         type: 'patch',          status: 'waiting', latestMessage: '' },
  risk:           { name: 'Risk Agent',          type: 'risk',           status: 'waiting', latestMessage: '' },
  validation:     { name: 'Validation Agent',    type: 'validation',     status: 'waiting', latestMessage: '' },
  compliance:     { name: 'Compliance Agent',    type: 'compliance',     status: 'waiting', latestMessage: '' },
  report:         { name: 'Report Agent',        type: 'report',         status: 'waiting', latestMessage: '' },
  github_guardian:{ name: 'GitHub Guardian',     type: 'github_guardian',status: 'waiting', latestMessage: '' },
};

const AGENT_ORDER = [
  'scanner',
  'sast', 'dependency', 'secrets', 'api',
  'attack_chain',
  'poc', 'severity', 'patch', 'risk',
  'validation', 'compliance',
  'report',
  'github_guardian',
];

// ─── Page ─────────────────────────────────────────────────────────────────────
function AuditContent() {
  const params       = useParams();
  const searchParams = useSearchParams();
  const sessionId    = params.sessionId as string;
  const githubUrl    = searchParams.get('url') ?? '';

  const [agents,            setAgents]            = useState<Record<string, AgentState>>(INITIAL_AGENTS);
  const [termLines,         setTermLines]          = useState<TerminalLine[]>([]);
  const [vulns,             setVulns]              = useState<any[]>([]);
  const [chains,            setChains]             = useState<any[]>([]);
  const [riskData,          setRiskData]           = useState<any>(null);
  const [reportReady,       setReportReady]        = useState(false);
  const [totalRisk,         setTotalRisk]          = useState<number>(0);
  const [wsStatus,          setWsStatus]           = useState<string>('connecting');

  // Direction A state
  const [validationResults, setValidationResults] = useState<ValidationEvidence[]>([]);
  const [complianceMappings,setComplianceMappings] = useState<ComplianceMapping[]>([]);
  const [blastRadius,       setBlastRadius]        = useState<BlastRadius | null>(null);
  const [plainSummary,      setPlainSummary]       = useState<string>('');
  const [prCommentUrl,      setPrCommentUrl]       = useState<string>('');
  const [checkRunConclusion,setCheckRunConclusion] = useState<string>('');

  // Active right-panel tab
  const [rightTab, setRightTab] = useState<'findings' | 'validation' | 'compliance' | 'pr'>('findings');

  const wsRef = useRef<WebSocketManager | null>(null);

  const handleMessage = useCallback((event: AgentMessage) => {
    const { agent_name, agent_type, status, message, data, timestamp } = event;

    // Update agent state
    setAgents(prev => ({
      ...prev,
      [agent_type]: {
        name:          agent_name,
        type:          agent_type,
        status:        status as AgentStatus,
        latestMessage: message,
        completedAt:   status === 'done' ? timestamp : prev[agent_type]?.completedAt,
      },
    }));

    // Add terminal line
    const t  = new Date(timestamp * 1000);
    const ts = t.toTimeString().slice(0, 8);
    setTermLines(prev => [
      ...prev.slice(-499),
      { timestamp: ts, agentName: agent_name, agentType: agent_type, message },
    ]);

    // Handle structured data
    if (data) {
      const d = data as Record<string, unknown>;

      if (Array.isArray(d.vulnerabilities) && d.vulnerabilities.length > 0) {
        setVulns(prev => [...prev, ...d.vulnerabilities as any[]]);
      }
      if (Array.isArray(d.attack_chains)) {
        setChains(d.attack_chains as any[]);
      }
      if (Array.isArray(d.scored_vulnerabilities) && d.scored_vulnerabilities.length > 0) {
        setVulns(d.scored_vulnerabilities as any[]);
      }
      if (typeof d.total_risk_usd === 'number' || d.risk_breakdown) {
        setRiskData(d);
        if (typeof d.total_risk_usd === 'number') setTotalRisk(d.total_risk_usd);
      }
      if (d.pdf_ready === true) {
        setReportReady(true);
        if (typeof d.total_risk_usd === 'number') setTotalRisk(d.total_risk_usd);
      }

      // Direction A — validation phase
      if (Array.isArray(d.validation_results)) {
        setValidationResults(d.validation_results as ValidationEvidence[]);
        setRightTab('validation');
      }

      // Direction A — compliance phase
      if (Array.isArray(d.compliance_mappings)) {
        setComplianceMappings(d.compliance_mappings as ComplianceMapping[]);
        if (d.blast_radius) setBlastRadius(d.blast_radius as BlastRadius);
        if (typeof d.plain_language_summary === 'string') setPlainSummary(d.plain_language_summary);
        setRightTab('compliance');
      }

      // Direction A — GitHub Guardian phase
      if (typeof d.comment_url === 'string' && d.comment_url) {
        setPrCommentUrl(d.comment_url);
        if (typeof d.conclusion === 'string') setCheckRunConclusion(d.conclusion);
        setRightTab('pr');
      }
    }
  }, []);

  useEffect(() => {
    if (!githubUrl || !sessionId) return;
    const ws = new WebSocketManager(sessionId, githubUrl);
    wsRef.current = ws;
    ws.onStatusChange(setWsStatus);
    ws.onMessage(handleMessage);
    return () => ws.disconnect();
  }, [sessionId, githubUrl, handleMessage]);

  const repoName = githubUrl.replace('https://github.com/', '');

  // Build a validation map keyed by vuln_id for quick badge lookup
  const valByVuln: Record<string, ValidationEvidence> = {};
  for (const v of validationResults) valByVuln[v.vuln_id] = v;

  const rightTabs: { key: typeof rightTab; label: string; count?: number }[] = [
    { key: 'findings',   label: '🔍 Findings',   count: vulns.length },
    { key: 'validation', label: '🧪 Validation',  count: validationResults.length || undefined },
    { key: 'compliance', label: '📋 Compliance',  count: complianceMappings.length || undefined },
    { key: 'pr',         label: '🤖 PR Preview',  count: prCommentUrl ? 1 : undefined },
  ];

  return (
    <div className="min-h-screen bg-[#0d1117] flex flex-col">
      {/* Top bar */}
      <header className="border-b border-gray-800 px-4 py-3 flex items-center gap-4 bg-[#161b22]/80 backdrop-blur-sm sticky top-0 z-10">
        <Link href="/" className="text-gray-400 hover:text-gray-200 transition-colors">
          <ArrowLeft size={18} />
        </Link>
        <div className="flex-1 min-w-0">
          <div className="text-xs text-gray-500 font-mono">swarmaudit / {sessionId.slice(0, 8)}</div>
          <div className="text-sm font-medium text-gray-200 truncate">{repoName}</div>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span
            className="w-2 h-2 rounded-full"
            style={{
              backgroundColor:
                wsStatus === 'connected'    ? '#3fb950' :
                wsStatus === 'disconnected' ? '#888888' :
                wsStatus === 'error'        ? '#ff7b72' :
                '#ffa657',
            }}
          />
          <span className="text-gray-400 capitalize hidden sm:inline">{wsStatus}</span>
        </div>
      </header>

      {/* Main 3-column layout */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-[280px_1fr_360px] gap-0 min-h-0">

        {/* ── LEFT: Agent Flow ─────────────────────────────────────── */}
        <aside className="border-r border-gray-800 p-3 overflow-y-auto space-y-2 bg-[#0d1117]">
          <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest px-1 pt-1 mb-3">
            Agent Flow
          </h2>
          {AGENT_ORDER.map(type => {
            const a = agents[type];
            if (!a) return null;
            return (
              <AgentCard
                key={type}
                name={a.name}
                type={a.type}
                status={a.status}
                latestMessage={a.latestMessage}
                completedAt={a.completedAt}
              />
            );
          })}
        </aside>

        {/* ── CENTER: Live Terminal ─────────────────────────────────── */}
        <main className="flex flex-col min-h-0 border-r border-gray-800">
          <div className="flex-1 p-3 min-h-0" style={{ height: 'calc(100vh - 56px)' }}>
            <LiveTerminal
              lines={termLines}
              sessionId={sessionId}
              status={wsStatus}
            />
          </div>
        </main>

        {/* ── RIGHT: Results Panel ──────────────────────────────────── */}
        <aside className="overflow-y-auto bg-[#0d1117]">
          {/* Tab bar */}
          <div className="sticky top-0 z-10 bg-[#0d1117] border-b border-gray-800 flex">
            {rightTabs.map(tab => (
              <button
                key={tab.key}
                onClick={() => setRightTab(tab.key)}
                className={`flex-1 px-1 py-2 text-[10px] font-medium transition-colors ${
                  rightTab === tab.key
                    ? 'text-blue-400 border-b-2 border-blue-500'
                    : 'text-gray-500 hover:text-gray-300'
                }`}
              >
                {tab.label}
                {tab.count !== undefined && (
                  <span className="ml-1 rounded-full bg-gray-700 px-1.5 py-0.5 text-[9px]">
                    {tab.count}
                  </span>
                )}
              </button>
            ))}
          </div>

          <div className="p-3 space-y-4">
            {/* Report download — always visible */}
            <ReportViewer
              sessionId={sessionId}
              reportReady={reportReady}
              totalVulns={vulns.length}
              totalRisk={totalRisk}
            />

            {/* ── Findings tab ─────────────────────────────────────── */}
            {rightTab === 'findings' && (
              <>
                <AnimatePresence>
                  {riskData && (
                    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
                      <RiskDashboard riskData={riskData as Parameters<typeof RiskDashboard>[0]['riskData']} />
                    </motion.div>
                  )}
                </AnimatePresence>

                <AnimatePresence>
                  {chains.length > 0 && (
                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                      <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-3">
                        ⚡ Attack Chains ({chains.length})
                      </h2>
                      <div className="space-y-3">
                        {(chains as Parameters<typeof AttackChainGraph>[0]['chain'][]).map((chain) => (
                          <AttackChainGraph key={chain.id} chain={chain} />
                        ))}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>

                {vulns.length > 0 && (
                  <div>
                    <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-3">
                      🔍 Findings ({vulns.length})
                    </h2>
                    <div className="space-y-2">
                      <AnimatePresence>
                        {(vulns as Parameters<typeof VulnerabilityCard>[0]['vulnerability'][])
                          .slice(0, 30)
                          .map(v => (
                            <VulnerabilityCard key={v.id} vulnerability={v} />
                          ))}
                      </AnimatePresence>
                      {vulns.length > 30 && (
                        <p className="text-xs text-gray-500 text-center py-2">
                          +{vulns.length - 30} more in PDF report
                        </p>
                      )}
                    </div>
                  </div>
                )}

                {vulns.length === 0 && !reportReady && !riskData && (
                  <div className="text-center text-xs text-gray-600 py-8">
                    Findings will appear here as agents discover them…
                  </div>
                )}
              </>
            )}

            {/* ── Validation tab ───────────────────────────────────── */}
            {rightTab === 'validation' && (
              <div>
                <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-3">
                  🧪 Sandbox Validation
                </h2>
                {validationResults.length === 0 ? (
                  <p className="text-xs text-gray-600 py-4">
                    {agents['validation']?.status === 'waiting'
                      ? 'Validation phase not started yet…'
                      : 'No validation results available.'}
                  </p>
                ) : (
                  <div className="space-y-3">
                    {validationResults.map(ev => {
                      const vuln = vulns.find(v => v.id === ev.vuln_id);
                      return (
                        <div key={ev.vuln_id} className="rounded border border-gray-800 bg-gray-900 p-3">
                          <div className="flex items-start justify-between gap-2">
                            <span className="text-xs text-gray-300 font-medium truncate">
                              {vuln?.title ?? ev.vuln_id}
                            </span>
                            <ValidationBadge verdict={ev.verdict} durationMs={ev.duration_ms} />
                          </div>
                          <EvidencePanel evidence={ev} />
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* ── Compliance tab ───────────────────────────────────── */}
            {rightTab === 'compliance' && (
              <div>
                <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-3">
                  📋 Compliance Impact
                </h2>
                <ComplianceMatrix
                  mappings={complianceMappings}
                  blastRadius={blastRadius}
                  plainSummary={plainSummary}
                />
              </div>
            )}

            {/* ── PR Preview tab ───────────────────────────────────── */}
            {rightTab === 'pr' && (
              <div>
                <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-3">
                  🤖 GitHub PR Comment
                </h2>
                <PRCommentPreview
                  sessionId={sessionId}
                  findings={vulns}
                  validationResults={validationResults}
                  complianceMappings={complianceMappings}
                  riskData={riskData}
                  prCommentUrl={prCommentUrl}
                  checkRunConclusion={checkRunConclusion}
                />
              </div>
            )}
          </div>
        </aside>
      </div>
    </div>
  );
}

export default function AuditPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-[#0d1117]" />}>
      <AuditContent />
    </Suspense>
  );
}

// ─── Types ───────────────────────────────────────────────────────────────────
type AgentStatus = 'waiting' | 'thinking' | 'working' | 'done' | 'error';

interface AgentState {
  name:          string;
  type:          string;
  status:        AgentStatus;
  latestMessage: string;
  completedAt?:  number;
}

const INITIAL_AGENTS: Record<string, AgentState> = {
  scanner:      { name: 'Scanner Agent',      type: 'scanner',      status: 'waiting', latestMessage: '' },
  sast:         { name: 'SAST Agent',          type: 'sast',         status: 'waiting', latestMessage: '' },
  dependency:   { name: 'Dependency Agent',    type: 'dependency',   status: 'waiting', latestMessage: '' },
  secrets:      { name: 'Secrets Agent',       type: 'secrets',      status: 'waiting', latestMessage: '' },
  api:          { name: 'API Agent',           type: 'api',          status: 'waiting', latestMessage: '' },
  attack_chain: { name: 'Attack Chain Agent',  type: 'attack_chain', status: 'waiting', latestMessage: '' },
  poc:          { name: 'PoC Agent',           type: 'poc',          status: 'waiting', latestMessage: '' },
  severity:     { name: 'Severity Agent',      type: 'severity',     status: 'waiting', latestMessage: '' },
  patch:        { name: 'Patch Agent',         type: 'patch',        status: 'waiting', latestMessage: '' },
  risk:         { name: 'Risk Agent',          type: 'risk',         status: 'waiting', latestMessage: '' },
  report:       { name: 'Report Agent',        type: 'report',       status: 'waiting', latestMessage: '' },
};

const AGENT_ORDER = [
  'scanner',
  'sast', 'dependency', 'secrets', 'api',
  'attack_chain',
  'poc', 'severity', 'patch', 'risk',
  'report',
];

// ─── Page ─────────────────────────────────────────────────────────────────────
function AuditContent() {
  const params       = useParams();
  const searchParams = useSearchParams();
  const sessionId    = params.sessionId as string;
  const githubUrl    = searchParams.get('url') ?? '';

  const [agents,       setAgents]       = useState<Record<string, AgentState>>(INITIAL_AGENTS);
  const [termLines,    setTermLines]    = useState<TerminalLine[]>([]);
  const [vulns,        setVulns]        = useState<any[]>([]);
  const [chains,       setChains]       = useState<any[]>([]);
  const [riskData,     setRiskData]     = useState<any>(null);
  const [reportReady,  setReportReady]  = useState(false);
  const [totalRisk,    setTotalRisk]    = useState<number>(0);
  const [wsStatus,     setWsStatus]     = useState<string>('connecting');

  const wsRef = useRef<WebSocketManager | null>(null);

  const handleMessage = useCallback((event: AgentMessage) => {
    const { agent_name, agent_type, status, message, data, timestamp } = event;

    // Update agent state
    setAgents(prev => ({
      ...prev,
      [agent_type]: {
        name:          agent_name,
        type:          agent_type,
        status:        status as AgentStatus,
        latestMessage: message,
        completedAt:   status === 'done' ? timestamp : prev[agent_type]?.completedAt,
      },
    }));

    // Add terminal line
    const t  = new Date(timestamp * 1000);
    const ts = t.toTimeString().slice(0, 8);
    setTermLines(prev => [
      ...prev.slice(-499),
      { timestamp: ts, agentName: agent_name, agentType: agent_type, message },
    ]);

    // Handle structured data
    if (data) {
      const d = data as Record<string, unknown>;

      if (Array.isArray(d.vulnerabilities) && d.vulnerabilities.length > 0) {
        setVulns(prev => [...prev, ...d.vulnerabilities as any[]]);
      }
      if (Array.isArray(d.attack_chains)) {
        setChains(d.attack_chains as any[]);
      }
      if (Array.isArray(d.scored_vulnerabilities) && d.scored_vulnerabilities.length > 0) {
        // Replace vulns with scored versions
        setVulns(d.scored_vulnerabilities as any[]);
      }
      if (typeof d.total_risk_usd === 'number' || d.risk_breakdown) {
        setRiskData(d);
        if (typeof d.total_risk_usd === 'number') setTotalRisk(d.total_risk_usd);
      }
      if (d.pdf_ready === true) {
        setReportReady(true);
        if (typeof d.total_risk_usd === 'number') setTotalRisk(d.total_risk_usd);
      }
    }
  }, []);

  useEffect(() => {
    if (!githubUrl || !sessionId) return;
    const ws = new WebSocketManager(sessionId, githubUrl);
    wsRef.current = ws;
    ws.onStatusChange(setWsStatus);
    ws.onMessage(handleMessage);
    return () => ws.disconnect();
  }, [sessionId, githubUrl, handleMessage]);

  const repoName = githubUrl.replace('https://github.com/', '');

  return (
    <div className="min-h-screen bg-[#0d1117] flex flex-col">
      {/* Top bar */}
      <header className="border-b border-gray-800 px-4 py-3 flex items-center gap-4 bg-[#161b22]/80 backdrop-blur-sm sticky top-0 z-10">
        <Link href="/" className="text-gray-400 hover:text-gray-200 transition-colors">
          <ArrowLeft size={18} />
        </Link>
        <div className="flex-1 min-w-0">
          <div className="text-xs text-gray-500 font-mono">swarmaudit / {sessionId.slice(0, 8)}</div>
          <div className="text-sm font-medium text-gray-200 truncate">{repoName}</div>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span
            className="w-2 h-2 rounded-full"
            style={{
              backgroundColor:
                wsStatus === 'connected'    ? '#3fb950' :
                wsStatus === 'disconnected' ? '#888888' :
                wsStatus === 'error'        ? '#ff7b72' :
                '#ffa657',
            }}
          />
          <span className="text-gray-400 capitalize hidden sm:inline">{wsStatus}</span>
        </div>
      </header>

      {/* Main 3-column layout */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-[280px_1fr_340px] gap-0 min-h-0">

        {/* ── LEFT: Agent Flow ─────────────────────────────────────── */}
        <aside className="border-r border-gray-800 p-3 overflow-y-auto space-y-2 bg-[#0d1117]">
          <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest px-1 pt-1 mb-3">
            Agent Flow
          </h2>
          {AGENT_ORDER.map(type => {
            const a = agents[type];
            if (!a) return null;
            return (
              <AgentCard
                key={type}
                name={a.name}
                type={a.type}
                status={a.status}
                latestMessage={a.latestMessage}
                completedAt={a.completedAt}
              />
            );
          })}
        </aside>

        {/* ── CENTER: Live Terminal ─────────────────────────────────── */}
        <main className="flex flex-col min-h-0 border-r border-gray-800">
          <div className="flex-1 p-3 min-h-0" style={{ height: 'calc(100vh - 56px)' }}>
            <LiveTerminal
              lines={termLines}
              sessionId={sessionId}
              status={wsStatus}
            />
          </div>
        </main>

        {/* ── RIGHT: Results Panel ──────────────────────────────────── */}
        <aside className="overflow-y-auto p-3 space-y-4 bg-[#0d1117]">
          {/* Report download */}
          <ReportViewer
            sessionId={sessionId}
            reportReady={reportReady}
            totalVulns={vulns.length}
            totalRisk={totalRisk}
          />

          {/* Risk dashboard */}
          <AnimatePresence>
            {riskData && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
              >
                <RiskDashboard riskData={riskData as Parameters<typeof RiskDashboard>[0]['riskData']} />
              </motion.div>
            )}
          </AnimatePresence>

          {/* Attack chains */}
          <AnimatePresence>
            {chains.length > 0 && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-3">
                  ⚡ Attack Chains ({chains.length})
                </h2>
                <div className="space-y-3">
                  {(chains as Parameters<typeof AttackChainGraph>[0]['chain'][]).map((chain) => (
                    <AttackChainGraph key={chain.id} chain={chain} />
                  ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Vulnerabilities */}
          {vulns.length > 0 && (
            <div>
              <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-3">
                🔍 Findings ({vulns.length})
              </h2>
              <div className="space-y-2">
                <AnimatePresence>
                  {(vulns as Parameters<typeof VulnerabilityCard>[0]['vulnerability'][])
                    .slice(0, 30)
                    .map(v => (
                      <VulnerabilityCard key={v.id} vulnerability={v} />
                    ))}
                </AnimatePresence>
                {vulns.length > 30 && (
                  <p className="text-xs text-gray-500 text-center py-2">
                    +{vulns.length - 30} more in PDF report
                  </p>
                )}
              </div>
            </div>
          )}

          {vulns.length === 0 && !reportReady && !riskData && (
            <div className="text-center text-xs text-gray-600 py-8">
              Findings will appear here as agents discover them…
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}

export default function AuditPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-[#0d1117]" />}>
      <AuditContent />
    </Suspense>
  );
}
