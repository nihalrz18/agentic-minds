/**
 * PRCommentPreview — renders a preview of the GitHub PR comment that
 * SwarmAudit will post, using the same Markdown structure as the backend.
 */
'use client';

import React, { useState } from 'react';
import { ValidationEvidence, ComplianceMapping, ValidationVerdict } from '../lib/api';

interface Finding {
  id: string;
  title: string;
  severity: string;
  file_path?: string;
  owasp_category?: string;
  patch_diff?: string;
  description?: string;
}

interface Props {
  sessionId: string;
  findings: Finding[];
  validationResults: ValidationEvidence[];
  complianceMappings: ComplianceMapping[];
  riskData: { total_risk_usd?: number } | null;
  prCommentUrl?: string;
  checkRunConclusion?: string;
}

const VERDICT_BADGE: Record<ValidationVerdict, { label: string; cls: string }> = {
  VERIFIED:     { label: '🔴 VERIFIED',     cls: 'bg-red-900 text-red-200' },
  UNVERIFIED:   { label: '🟡 UNVERIFIED',   cls: 'bg-yellow-900 text-yellow-200' },
  INCONCLUSIVE: { label: '🟠 INCONCLUSIVE', cls: 'bg-orange-900 text-orange-200' },
  SKIPPED:      { label: '⚪ SKIPPED',      cls: 'bg-gray-800 text-gray-400' },
};

const SEV_CLS: Record<string, string> = {
  CRITICAL: 'text-red-400',
  HIGH:     'text-orange-400',
  MEDIUM:   'text-yellow-400',
  LOW:      'text-green-400',
  INFO:     'text-blue-400',
};

const CONCLUSION_BADGE: Record<string, { label: string; cls: string }> = {
  action_required: { label: '🔴 Action Required', cls: 'bg-red-800 text-white' },
  neutral:         { label: '🟡 Review Needed',   cls: 'bg-yellow-800 text-white' },
  success:         { label: '✅ Passed',           cls: 'bg-green-800 text-white' },
};

export function PRCommentPreview({
  sessionId,
  findings,
  validationResults,
  complianceMappings,
  riskData,
  prCommentUrl,
  checkRunConclusion,
}: Props) {
  const [expanded, setExpanded] = useState(false);

  const valMap: Record<string, ValidationEvidence> = {};
  for (const v of validationResults) valMap[v.vuln_id] = v;

  const compMap: Record<string, string[]> = {};
  for (const m of complianceMappings) {
    if (!compMap[m.vuln_id]) compMap[m.vuln_id] = [];
    if (!compMap[m.vuln_id].includes(m.framework)) compMap[m.vuln_id].push(m.framework);
  }

  const crit  = findings.filter(f => f.severity === 'CRITICAL').length;
  const high  = findings.filter(f => f.severity === 'HIGH').length;
  const verified = validationResults.filter(v => v.verdict === 'VERIFIED').length;
  const totalRisk = riskData?.total_risk_usd ?? 0;

  const conclusion = checkRunConclusion ?? (
    verified > 0 ? 'action_required' : findings.length > 0 ? 'neutral' : 'success'
  );
  const badge = CONCLUSION_BADGE[conclusion] ?? CONCLUSION_BADGE.neutral;

  return (
    <div className="rounded-lg border border-gray-700 bg-gray-900 overflow-hidden">
      {/* Header bar */}
      <div className="flex items-center justify-between px-4 py-3 bg-gray-800 border-b border-gray-700">
        <div className="flex items-center gap-2">
          <span className="text-sm font-semibold text-white">GitHub PR Comment Preview</span>
          <span className={`rounded px-2 py-0.5 text-xs font-semibold ${badge.cls}`}>
            {badge.label}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {prCommentUrl && (
            <a
              href={prCommentUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-blue-400 hover:underline"
            >
              View on GitHub ↗
            </a>
          )}
          <button
            onClick={() => setExpanded(!expanded)}
            className="text-gray-400 hover:text-white text-xs"
          >
            {expanded ? '▲ Collapse' : '▼ Expand'}
          </button>
        </div>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-4 divide-x divide-gray-700 border-b border-gray-700">
        {[
          ['Findings', findings.length, ''],
          ['Crit / High', `${crit} / ${high}`, 'text-orange-400'],
          ['Verified', verified, verified > 0 ? 'text-red-400' : 'text-gray-400'],
          ['Exposure', `$${totalRisk.toLocaleString()}`, 'text-yellow-400'],
        ].map(([label, value, cls]) => (
          <div key={label as string} className="px-3 py-2 text-center">
            <div className={`text-sm font-bold ${cls || 'text-white'}`}>{value}</div>
            <div className="text-[10px] text-gray-500 uppercase tracking-wide">{label}</div>
          </div>
        ))}
      </div>

      {/* Findings table */}
      {expanded && (
        <div className="overflow-x-auto p-4">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-gray-700 text-gray-400">
                <th className="pb-1 pr-3 text-left">Finding</th>
                <th className="pb-1 pr-3 text-left">Severity</th>
                <th className="pb-1 pr-3 text-left">Validation</th>
                <th className="pb-1 pr-3 text-left">Compliance</th>
                <th className="pb-1 text-left">Patch</th>
              </tr>
            </thead>
            <tbody>
              {findings.slice(0, 15).map(f => {
                const ev = valMap[f.id];
                const verdict = ev?.verdict ?? 'SKIPPED';
                const vBadge = VERDICT_BADGE[verdict];
                const fws = compMap[f.id]?.slice(0, 3).join(', ') ?? '—';
                return (
                  <tr key={f.id} className="border-b border-gray-800 hover:bg-gray-800">
                    <td className="py-1 pr-3 text-gray-200 max-w-[200px] truncate">
                      {f.title}
                    </td>
                    <td className={`py-1 pr-3 font-semibold ${SEV_CLS[f.severity] ?? ''}`}>
                      {f.severity}
                    </td>
                    <td className="py-1 pr-3">
                      <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${vBadge.cls}`}>
                        {vBadge.label}
                      </span>
                    </td>
                    <td className="py-1 pr-3 text-gray-400">{fws}</td>
                    <td className="py-1">
                      {f.patch_diff
                        ? <span className="text-green-400">✅</span>
                        : <span className="text-gray-600">—</span>
                      }
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {findings.length > 15 && (
            <p className="mt-2 text-xs text-gray-500">
              + {findings.length - 15} more findings in full report
            </p>
          )}
        </div>
      )}
    </div>
  );
}
