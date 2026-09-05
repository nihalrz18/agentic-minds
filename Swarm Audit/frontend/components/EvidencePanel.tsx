/**
 * EvidencePanel — collapsible sandbox evidence detail for a single finding.
 * Shows stdout, method, duration, and notes from the ValidationEvidence record.
 */
'use client';

import React, { useState } from 'react';
import { ValidationEvidence } from '../lib/api';
import { ValidationBadge } from './ValidationBadge';

interface Props {
  evidence: ValidationEvidence;
}

export function EvidencePanel({ evidence }: Props) {
  const [open, setOpen] = useState(false);

  return (
    <div className="mt-2 rounded border border-gray-700 bg-gray-900 text-sm">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center justify-between px-3 py-2 text-left text-gray-300 hover:bg-gray-800 transition-colors"
      >
        <span className="flex items-center gap-2">
          <ValidationBadge verdict={evidence.verdict} durationMs={evidence.duration_ms} />
          <span className="text-gray-400 text-xs font-mono">{evidence.method}</span>
        </span>
        <span className="text-gray-500 text-xs">{open ? '▲ hide' : '▼ evidence'}</span>
      </button>

      {open && (
        <div className="border-t border-gray-700 px-3 py-2 space-y-2">
          {evidence.command_executed && (
            <div>
              <span className="text-gray-500 text-xs uppercase tracking-wide">Command</span>
              <pre className="mt-1 rounded bg-black p-2 text-xs text-green-400 overflow-x-auto">
                {evidence.command_executed}
              </pre>
            </div>
          )}
          {evidence.stdout_excerpt && (
            <div>
              <span className="text-gray-500 text-xs uppercase tracking-wide">Stdout</span>
              <pre className="mt-1 rounded bg-black p-2 text-xs text-gray-300 overflow-x-auto max-h-32">
                {evidence.stdout_excerpt}
              </pre>
            </div>
          )}
          {evidence.stderr_excerpt && (
            <div>
              <span className="text-gray-500 text-xs uppercase tracking-wide">Stderr</span>
              <pre className="mt-1 rounded bg-black p-2 text-xs text-red-400 overflow-x-auto max-h-24">
                {evidence.stderr_excerpt}
              </pre>
            </div>
          )}
          {evidence.notes && (
            <p className="text-gray-400 text-xs italic">{evidence.notes}</p>
          )}
          <div className="flex gap-4 text-xs text-gray-500">
            {evidence.container_image && (
              <span>Image: <code className="text-gray-300">{evidence.container_image}</code></span>
            )}
            <span>Exit: <code className="text-gray-300">{evidence.exit_code ?? 'n/a'}</code></span>
            <span>Duration: <code className="text-gray-300">{evidence.duration_ms}ms</code></span>
            {evidence.timeout_hit && (
              <span className="text-orange-400 font-semibold">⚠ Timeout</span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
