/**
 * ComplianceMatrix — shows framework blast radius and top impacted controls.
 * Rendered in the audit dashboard after the compliance phase completes.
 */
'use client';

import React, { useState } from 'react';
import { ComplianceMapping, BlastRadius } from '../lib/api';

interface Props {
  mappings: ComplianceMapping[];
  blastRadius: BlastRadius | null;
  plainSummary?: string;
}

const FRAMEWORK_COLORS: Record<string, string> = {
  'SOC 2':    'bg-blue-700',
  'HIPAA':    'bg-purple-700',
  'PCI-DSS':  'bg-red-700',
  'GDPR':     'bg-green-700',
  'MITRE':    'bg-orange-700',
};

export function ComplianceMatrix({ mappings, blastRadius, plainSummary }: Props) {
  const [activeFramework, setActiveFramework] = useState<string | null>(null);

  const fwCounts = blastRadius?.framework_counts ?? {};
  const topControls = blastRadius?.top_high_risk_controls ?? [];

  const frameworks = Object.entries(fwCounts).sort(([, a], [, b]) => b - a);

  const filteredMappings = activeFramework
    ? mappings.filter(m => m.framework === activeFramework)
    : mappings;

  if (!mappings.length) {
    return (
      <div className="rounded-lg border border-gray-700 bg-gray-900 p-4 text-gray-400 text-sm">
        Compliance mapping not yet available.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Executive summary */}
      {plainSummary && (
        <div className="rounded-lg border border-blue-800 bg-blue-950/40 px-4 py-3 text-sm text-blue-200">
          {plainSummary}
        </div>
      )}

      {/* Framework blast radius bars */}
      <div className="rounded-lg border border-gray-700 bg-gray-900 p-4">
        <h3 className="mb-3 text-sm font-semibold text-gray-200 uppercase tracking-wide">
          Framework Exposure
        </h3>
        <div className="space-y-2">
          {frameworks.map(([fw, count]) => {
            const pct = Math.min(100, (count / Math.max(...Object.values(fwCounts))) * 100);
            const colorClass = FRAMEWORK_COLORS[fw] ?? 'bg-gray-600';
            return (
              <button
                key={fw}
                onClick={() => setActiveFramework(activeFramework === fw ? null : fw)}
                className={`w-full text-left rounded p-2 transition-colors ${
                  activeFramework === fw ? 'ring-2 ring-white/30' : ''
                } hover:bg-gray-800`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-medium text-gray-300">{fw}</span>
                  <span className="text-xs text-gray-400">{count} controls</span>
                </div>
                <div className="h-1.5 w-full rounded bg-gray-700">
                  <div
                    className={`h-full rounded ${colorClass}`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Top impacted controls */}
      {topControls.length > 0 && (
        <div className="rounded-lg border border-gray-700 bg-gray-900 p-4">
          <h3 className="mb-3 text-sm font-semibold text-gray-200 uppercase tracking-wide">
            Top Impacted Controls
          </h3>
          <div className="space-y-1">
            {topControls.slice(0, 8).map((c, i) => (
              <div
                key={i}
                className="flex items-start gap-2 rounded px-2 py-1 text-xs hover:bg-gray-800"
              >
                <span className={`mt-0.5 shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold text-white ${
                  FRAMEWORK_COLORS[c.framework] ?? 'bg-gray-600'
                }`}>
                  {c.framework}
                </span>
                <span className="font-mono text-gray-400">{c.control_id}</span>
                <span className="text-gray-300 truncate">{c.control_name}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filtered mapping detail */}
      {activeFramework && (
        <div className="rounded-lg border border-gray-700 bg-gray-900 p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-gray-200">
              {activeFramework} Controls at Risk
            </h3>
            <button
              onClick={() => setActiveFramework(null)}
              className="text-gray-500 hover:text-gray-300 text-xs"
            >
              ✕ clear filter
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-gray-700 text-gray-400">
                  <th className="pb-1 pr-3 text-left font-medium">Control</th>
                  <th className="pb-1 pr-3 text-left font-medium">Name</th>
                  <th className="pb-1 text-left font-medium">OWASP</th>
                </tr>
              </thead>
              <tbody>
                {filteredMappings.slice(0, 20).map((m, i) => (
                  <tr key={i} className="border-b border-gray-800 hover:bg-gray-800">
                    <td className="py-1 pr-3 font-mono text-gray-300">{m.control_id}</td>
                    <td className="py-1 pr-3 text-gray-300 truncate max-w-[200px]">{m.control_name}</td>
                    <td className="py-1 text-gray-400">{m.owasp_category}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
