'use client';

import { motion } from 'framer-motion';
import {
  Search, Shield, Package, Key, Globe, Link2,
  Code2, Gauge, Wrench, DollarSign, FileText,
} from 'lucide-react';

interface AgentCardProps {
  name:          string;
  type:          string;
  status:        'waiting' | 'thinking' | 'working' | 'done' | 'error';
  latestMessage: string;
  completedAt?:  number;
}

const AGENT_CONFIG: Record<string, { icon: React.ReactNode; color: string; label: string }> = {
  scanner:      { icon: <Search     size={16} />, color: '#58a6ff', label: 'Scanner'       },
  sast:         { icon: <Shield     size={16} />, color: '#ffa657', label: 'SAST'          },
  dependency:   { icon: <Package    size={16} />, color: '#f0883e', label: 'Dependencies'  },
  secrets:      { icon: <Key        size={16} />, color: '#ff7b72', label: 'Secrets'       },
  api:          { icon: <Globe      size={16} />, color: '#a5d6ff', label: 'API'           },
  attack_chain: { icon: <Link2      size={16} />, color: '#ff4444', label: 'Attack Chain'  },
  poc:          { icon: <Code2      size={16} />, color: '#ff7b72', label: 'PoC'           },
  severity:     { icon: <Gauge      size={16} />, color: '#bc8cff', label: 'Severity'      },
  patch:        { icon: <Wrench     size={16} />, color: '#3fb950', label: 'Patch'         },
  risk:         { icon: <DollarSign size={16} />, color: '#ffd700', label: 'Risk'          },
  report:       { icon: <FileText   size={16} />, color: '#79c0ff', label: 'Report'        },
};

const STATUS_DOT: Record<string, string> = {
  waiting:  'bg-gray-600',
  thinking: 'bg-yellow-400 animate-pulse',
  working:  'bg-blue-400 animate-pulse',
  done:     'bg-green-400',
  error:    'bg-red-500',
};

export default function AgentCard({ name, type, status, latestMessage }: AgentCardProps) {
  const cfg   = AGENT_CONFIG[type] ?? AGENT_CONFIG.scanner;
  const isDone = status === 'done';
  const isWork = status === 'working' || status === 'thinking';

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={`relative rounded-lg border p-3 transition-all duration-300
        ${isDone  ? 'border-green-800/60 bg-green-950/20' : ''}
        ${isWork  ? 'border-blue-700/60  bg-blue-950/20'  : ''}
        ${status === 'error'   ? 'border-red-700/60   bg-red-950/20'   : ''}
        ${status === 'waiting' ? 'border-gray-700/40  bg-gray-900/30'  : ''}
      `}
    >
      {/* Pulsing ring for active states */}
      {isWork && (
        <motion.div
          className="absolute inset-0 rounded-lg border border-blue-500/40"
          animate={{ opacity: [0.4, 1, 0.4] }}
          transition={{ repeat: Infinity, duration: 1.5 }}
        />
      )}

      <div className="flex items-start gap-2">
        {/* Icon */}
        <motion.div
          style={{ color: cfg.color }}
          animate={
            isWork  ? { rotate: [0, 360] } :
            isDone  ? { scale: [1, 1.3, 1] } :
            {}
          }
          transition={
            isWork ? { repeat: Infinity, duration: 2, ease: 'linear' } :
            isDone ? { duration: 0.4 } :
            {}
          }
          className="mt-0.5 shrink-0"
        >
          {cfg.icon}
        </motion.div>

        {/* Content */}
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-gray-200 truncate">{name}</span>
            <span className={`h-2 w-2 rounded-full shrink-0 ${STATUS_DOT[status]}`} />
          </div>
          <p className="text-xs text-gray-400 mt-0.5 truncate leading-relaxed">
            {latestMessage || 'Waiting…'}
          </p>
        </div>
      </div>
    </motion.div>
  );
}
