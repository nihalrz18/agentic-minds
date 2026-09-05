'use client';

import { useEffect, useRef, useState } from 'react';

interface ChainStep {
  step_num:    number;
  title:       string;
  layer:       string;
  vuln_id?:    string;
  description?: string;
  enables_next?: string;
}

interface AttackChain {
  id:                   string;
  name:                 string;
  chain_steps:          ChainStep[];
  exploit_path:         string;
  risk_level:           string;
  cvss_overall:         number;
  business_impact_usd:  number;
  fix_sequence?:        string[];
}

interface AttackChainGraphProps {
  chain: AttackChain;
}

const LAYER_COLORS: Record<string, string> = {
  code:       '#58a6ff',
  dependency: '#f0883e',
  secret:     '#ff7b72',
  api:        '#bc8cff',
};

const RISK_COLORS: Record<string, string> = {
  CRITICAL: '#c0392b',
  HIGH:     '#e67e22',
  MEDIUM:   '#f39c12',
  LOW:      '#27ae60',
};

export default function AttackChainGraph({ chain }: AttackChainGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [rendered, setRendered] = useState(false);
  const [error, setError]       = useState(false);
  const id = `mermaid-${chain.id.replace(/[^a-zA-Z0-9]/g, '')}`;

  useEffect(() => {
    let cancelled = false;

    async function render() {
      try {
        const mermaid = (await import('mermaid')).default;
        mermaid.initialize({
          startOnLoad: false,
          theme: 'dark',
          themeVariables: {
            background:   '#0d1117',
            primaryColor: '#1f6feb',
            lineColor:    '#58a6ff',
          },
        });

        const steps = chain.chain_steps;
        const nodes = steps
          .map((s, i) => {
            const safeTitle = s.title.replace(/"/g, "'").slice(0, 40);
            const color     = LAYER_COLORS[s.layer] ?? '#58a6ff';
            const nodeId    = `N${i}`;
            return `  ${nodeId}["${safeTitle}<br/>(${s.layer})"]`;
          })
          .join('\n');

        const edges = steps
          .slice(0, -1)
          .map((_, i) => `  N${i} --> N${i + 1}`)
          .join('\n');

        const lastIdx  = steps.length;
        const impactColor = RISK_COLORS[chain.risk_level] ?? '#e67e22';
        const diagram  = `graph LR
${nodes}
  N${lastIdx - 1} --> IMPACT["⚡ IMPACT: ${chain.risk_level}"]
${edges}
`;

        if (containerRef.current && !cancelled) {
          const { svg } = await mermaid.render(id, diagram);
          containerRef.current.innerHTML = svg;
          setRendered(true);
        }
      } catch {
        if (!cancelled) setError(true);
      }
    }

    render();
    return () => { cancelled = true; };
  }, [chain, id]);

  const riskColor = RISK_COLORS[chain.risk_level] ?? '#e67e22';

  return (
    <div className="rounded-lg border border-gray-700/60 bg-gray-900/40 overflow-hidden">
      {/* Chain header */}
      <div className="px-4 py-3 border-b border-gray-700/40">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <h3 className="text-sm font-semibold text-gray-200">{chain.name}</h3>
          <div className="flex items-center gap-3 text-xs">
            <span style={{ color: riskColor }} className="font-bold">{chain.risk_level}</span>
            <span className="text-gray-400">CVSS {chain.cvss_overall?.toFixed(1)}</span>
            <span className="text-yellow-400 font-semibold">
              ${(chain.business_impact_usd ?? 0).toLocaleString()}
            </span>
          </div>
        </div>
      </div>

      {/* Mermaid diagram */}
      <div className="p-3 overflow-x-auto">
        {error ? (
          /* Fallback: text-based chain visualization */
          <div className="flex items-center gap-1 flex-wrap text-xs">
            {chain.chain_steps.map((step, i) => (
              <div key={i} className="flex items-center gap-1">
                <span
                  className="px-2 py-1 rounded text-xs font-mono"
                  style={{
                    backgroundColor: (LAYER_COLORS[step.layer] ?? '#58a6ff') + '22',
                    color:           LAYER_COLORS[step.layer] ?? '#58a6ff',
                    borderColor:     LAYER_COLORS[step.layer] ?? '#58a6ff',
                    border:          '1px solid',
                  }}
                >
                  {step.title.slice(0, 30)}
                </span>
                {i < chain.chain_steps.length - 1 && (
                  <span className="text-gray-500">→</span>
                )}
              </div>
            ))}
            <span className="text-red-400 ml-1">→ ⚡ {chain.risk_level}</span>
          </div>
        ) : (
          <div ref={containerRef} className="text-xs text-gray-500">
            {!rendered && 'Rendering diagram…'}
          </div>
        )}
      </div>

      {/* Exploit path */}
      {chain.exploit_path && (
        <div className="px-4 pb-3">
          <p className="text-xs text-gray-400 leading-relaxed">{chain.exploit_path}</p>
        </div>
      )}
    </div>
  );
}
