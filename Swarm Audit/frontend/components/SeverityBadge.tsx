'use client';

interface SeverityBadgeProps {
  severity: string;
  score?: number;
}

const SEVERITY_CONFIG: Record<string, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: 'bg-red-900/50',    text: 'text-red-400',    border: 'border-red-500' },
  HIGH:     { bg: 'bg-orange-900/50', text: 'text-orange-400', border: 'border-orange-500' },
  MEDIUM:   { bg: 'bg-yellow-900/50', text: 'text-yellow-400', border: 'border-yellow-500' },
  LOW:      { bg: 'bg-green-900/50',  text: 'text-green-400',  border: 'border-green-500' },
  INFO:     { bg: 'bg-blue-900/50',   text: 'text-blue-400',   border: 'border-blue-500' },
};

export default function SeverityBadge({ severity, score }: SeverityBadgeProps) {
  const cfg = SEVERITY_CONFIG[severity?.toUpperCase()] ?? SEVERITY_CONFIG.INFO;
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-bold
        ${cfg.bg} ${cfg.text} ${cfg.border}`}
    >
      {severity?.toUpperCase()}
      {score !== undefined && score > 0 && (
        <span className="opacity-75 font-normal ml-0.5">{score.toFixed(1)}</span>
      )}
    </span>
  );
}
