/**
 * ValidationBadge — shows the sandbox verdict for a single finding.
 * Used inline in the findings table on the audit dashboard.
 */
import React from 'react';
import { ValidationVerdict } from '../lib/api';

interface Props {
  verdict: ValidationVerdict | undefined;
  durationMs?: number;
}

const CONFIG: Record<ValidationVerdict, { bg: string; text: string; icon: string; label: string }> = {
  VERIFIED:     { bg: 'bg-red-600',    text: 'text-white',       icon: '🔴', label: 'Verified' },
  UNVERIFIED:   { bg: 'bg-yellow-500', text: 'text-gray-900',    icon: '🟡', label: 'Unverified' },
  INCONCLUSIVE: { bg: 'bg-orange-500', text: 'text-white',       icon: '🟠', label: 'Inconclusive' },
  SKIPPED:      { bg: 'bg-gray-600',   text: 'text-gray-300',    icon: '⚪', label: 'Skipped' },
};

export function ValidationBadge({ verdict, durationMs }: Props) {
  if (!verdict) {
    return (
      <span className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-medium bg-gray-700 text-gray-400">
        ⚪ No data
      </span>
    );
  }

  const cfg = CONFIG[verdict];
  return (
    <span
      title={durationMs !== undefined ? `Validation took ${durationMs}ms` : undefined}
      className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-semibold ${cfg.bg} ${cfg.text}`}
    >
      {cfg.icon} {cfg.label}
    </span>
  );
}
