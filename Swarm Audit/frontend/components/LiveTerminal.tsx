'use client';

import { useEffect, useRef } from 'react';

export interface TerminalLine {
  timestamp: string;
  agentName: string;
  agentType: string;
  message:   string;
}

interface LiveTerminalProps {
  lines:     TerminalLine[];
  sessionId: string;
  status:    string;
}

const AGENT_COLORS: Record<string, string> = {
  scanner:      '#58a6ff',
  sast:         '#ffa657',
  dependency:   '#f0883e',
  secrets:      '#ff7b72',
  api:          '#a5d6ff',
  attack_chain: '#ff4444',
  poc:          '#ff7b72',
  severity:     '#bc8cff',
  patch:        '#3fb950',
  risk:         '#ffd700',
  report:       '#79c0ff',
  system:       '#888888',
};

export default function LiveTerminal({ lines, sessionId, status }: LiveTerminalProps) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [lines]);

  const wsColor =
    status === 'connected'    ? '#3fb950' :
    status === 'disconnected' ? '#888888' :
    status === 'error'        ? '#ff7b72' :
    '#ffa657';

  return (
    <div className="flex flex-col h-full rounded-xl border border-gray-700/60 overflow-hidden bg-[#0d1117]">
      {/* Terminal header */}
      <div className="flex items-center justify-between px-4 py-2 bg-gray-900/80 border-b border-gray-700/60 shrink-0">
        <div className="flex items-center gap-2">
          <div className="flex gap-1.5">
            <span className="w-3 h-3 rounded-full bg-red-500/80" />
            <span className="w-3 h-3 rounded-full bg-yellow-500/80" />
            <span className="w-3 h-3 rounded-full bg-green-500/80" />
          </div>
          <span className="text-xs font-mono text-gray-400 ml-2">
            🔐 SWARMAUDIT v1.0 — SESSION {sessionId.slice(0, 8).toUpperCase()}
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full" style={{ backgroundColor: wsColor }} />
          <span className="text-xs text-gray-500 font-mono capitalize">{status}</span>
        </div>
      </div>

      {/* Terminal body */}
      <div className="flex-1 overflow-y-auto p-3 font-mono text-xs leading-relaxed">
        {lines.length === 0 ? (
          <div className="text-gray-600 text-xs">
            <span className="text-green-400">$</span> Waiting for audit to start…
          </div>
        ) : (
          lines.map((line, i) => {
            const color = AGENT_COLORS[line.agentType] ?? '#888888';
            return (
              <div key={i} className="flex items-start gap-2 mb-0.5 group">
                <span className="text-gray-600 shrink-0 select-none">{line.timestamp}</span>
                <span
                  className="font-semibold shrink-0"
                  style={{ color }}
                >
                  [{line.agentName}]
                </span>
                <span className="text-gray-300 break-words min-w-0">{line.message}</span>
              </div>
            );
          })
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
