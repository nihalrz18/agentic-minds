'use client';

import { motion } from 'framer-motion';

interface RiskBreakdown {
  technical_breach:    number;
  regulatory_fines:    number;
  reputational_damage: number;
}

interface RiskData {
  total_risk_usd:            number;
  regulatory_fine_usd:       number;
  breach_cost_per_record_usd?: number;
  affected_records_est?:     number;
  fix_investment_hours?:     number;
  fix_cost_usd?:             number;
  roi_ratio?:                number;
  risk_breakdown?:           RiskBreakdown;
  risk_narrative?:           string;
  critical_count?:           number;
  high_count?:               number;
  medium_count?:             number;
  low_count?:                number;
}

interface RiskDashboardProps {
  riskData: RiskData;
}

function formatUSD(n: number): string {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000)     return `$${(n / 1_000).toFixed(0)}K`;
  return `$${n.toFixed(0)}`;
}

function SecurityScore({ vulns }: { vulns: { c?: number; h?: number; m?: number; l?: number } }) {
  const score = Math.max(0, 100 - ((vulns.c ?? 0) * 10 + (vulns.h ?? 0) * 5 + (vulns.m ?? 0) * 2 + (vulns.l ?? 0)));
  const color = score >= 70 ? '#3fb950' : score >= 40 ? '#f39c12' : '#c0392b';
  return (
    <div className="text-center">
      <div className="text-4xl font-bold" style={{ color }}>{score}</div>
      <div className="text-xs text-gray-400 mt-1">Security Score</div>
      <div className="w-full bg-gray-800 rounded-full h-2 mt-2">
        <div
          className="h-2 rounded-full transition-all duration-1000"
          style={{ width: `${score}%`, backgroundColor: color }}
        />
      </div>
    </div>
  );
}

function BreakdownBar({ label, value, total, color }: { label: string; value: number; total: number; color: string }) {
  const pct = total > 0 ? Math.min(100, (value / total) * 100) : 0;
  return (
    <div>
      <div className="flex justify-between text-xs mb-1">
        <span className="text-gray-400">{label}</span>
        <span className="text-gray-300 font-mono">{formatUSD(value)}</span>
      </div>
      <div className="w-full bg-gray-800 rounded-full h-1.5">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.8, ease: 'easeOut' }}
          className="h-1.5 rounded-full"
          style={{ backgroundColor: color }}
        />
      </div>
    </div>
  );
}

export default function RiskDashboard({ riskData: r }: RiskDashboardProps) {
  const total       = r.total_risk_usd ?? 0;
  const totalColor  = total >= 500_000 ? '#c0392b' : total >= 100_000 ? '#e67e22' : '#3fb950';
  const breakdown   = r.risk_breakdown ?? { technical_breach: 0, regulatory_fines: 0, reputational_damage: 0 };

  return (
    <div className="rounded-lg border border-gray-700/60 bg-gray-900/40 p-4 space-y-4">
      {/* Total risk */}
      <div className="text-center py-2">
        <motion.div
          initial={{ scale: 0.5, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ type: 'spring', stiffness: 200 }}
          className="text-4xl font-bold tracking-tight"
          style={{ color: totalColor }}
        >
          {formatUSD(total)}
        </motion.div>
        <p className="text-xs text-gray-400 mt-1">Estimated Breach Exposure</p>
      </div>

      {/* Breakdown bars */}
      {total > 0 && (
        <div className="space-y-2">
          <BreakdownBar label="Technical Breach"    value={breakdown.technical_breach}    total={total} color="#c0392b" />
          <BreakdownBar label="Regulatory Fines"    value={breakdown.regulatory_fines}    total={total} color="#e67e22" />
          <BreakdownBar label="Reputational Damage" value={breakdown.reputational_damage} total={total} color="#bc8cff" />
        </div>
      )}

      {/* ROI section */}
      {r.roi_ratio !== undefined && r.roi_ratio > 0 && (
        <div className="grid grid-cols-2 gap-3 pt-2 border-t border-gray-700/40">
          <div className="text-center">
            <div className="text-lg font-bold text-gray-200">
              {r.fix_investment_hours?.toFixed(0) ?? '?'} hrs
            </div>
            <div className="text-xs text-gray-500">Fix Cost</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-bold text-green-400">{r.roi_ratio?.toFixed(0)}x</div>
            <div className="text-xs text-gray-500">ROI of Fixing</div>
          </div>
        </div>
      )}

      {/* Security score */}
      <div className="pt-2 border-t border-gray-700/40">
        <SecurityScore vulns={{
          c: r.critical_count, h: r.high_count,
          m: r.medium_count,   l: r.low_count,
        }} />
      </div>

      {/* Narrative */}
      {r.risk_narrative && (
        <p className="text-xs text-gray-400 leading-relaxed pt-2 border-t border-gray-700/40">
          {r.risk_narrative}
        </p>
      )}
    </div>
  );
}
