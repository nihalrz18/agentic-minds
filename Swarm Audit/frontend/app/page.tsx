'use client';

import { motion } from 'framer-motion';
import { Shield, Zap, DollarSign, Clock, Users, Code2, Package, Key, Globe, Link2, Gauge, Wrench, FileText } from 'lucide-react';
import AuditForm from '../components/AuditForm';

const STATS = [
  { icon: Clock,   value: '4 min vs 2 weeks', label: 'Time to report' },
  { icon: DollarSign, value: '$0 vs $15,000', label: 'Cost of audit'  },
  { icon: Users,   value: '9 AI Agents',       label: '0 manual work'  },
];

const AGENTS = [
  { icon: Shield,     name: 'Scanner Agent',      color: '#58a6ff', desc: 'Clones repo, maps structure & tech stack' },
  { icon: Code2,      name: 'SAST Agent',          color: '#ffa657', desc: 'OWASP Top 10 via Semgrep rules' },
  { icon: Package,    name: 'Dependency Agent',    color: '#f0883e', desc: 'CVE checks via OSV.dev API' },
  { icon: Key,        name: 'Secrets Agent',       color: '#ff7b72', desc: 'Hardcoded credential detection' },
  { icon: Globe,      name: 'API Agent',           color: '#a5d6ff', desc: 'Endpoint & auth gap discovery' },
  { icon: Link2,      name: 'Attack Chain Agent',  color: '#ff4444', desc: 'Cross-layer exploit path synthesis' },
  { icon: Code2,      name: 'PoC Agent',           color: '#ff7b72', desc: 'Working exploit script generation' },
  { icon: Gauge,      name: 'Severity Agent',      color: '#bc8cff', desc: 'CVSS 3.1 scoring & ranking' },
  { icon: Wrench,     name: 'Patch Agent',         color: '#3fb950', desc: 'Context-aware code fixes' },
  { icon: DollarSign, name: 'Risk Agent',          color: '#ffd700', desc: 'Business risk in USD (IBM formula)' },
  { icon: FileText,   name: 'Report Agent',        color: '#79c0ff', desc: 'Professional PDF pentest report' },
];

export default function HomePage() {
  return (
    <main className="min-h-screen bg-[#0d1117] grid-bg">
      {/* Hero section */}
      <section className="relative flex flex-col items-center justify-center px-4 py-24 text-center overflow-hidden">
        {/* Radial glow */}
        <div className="absolute inset-0 bg-gradient-radial from-blue-900/20 via-transparent to-transparent pointer-events-none" />

        {/* Animated shield */}
        <motion.div
          animate={{ scale: [1, 1.05, 1] }}
          transition={{ repeat: Infinity, duration: 3, ease: 'easeInOut' }}
          className="shield-glow mb-8"
        >
          <Shield size={80} className="text-blue-400" strokeWidth={1.5} />
        </motion.div>

        {/* Headline */}
        <motion.h1
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="text-4xl md:text-6xl font-bold text-white mb-4 max-w-4xl leading-tight"
        >
          Autonomous Security
          <br />
          <span className="text-blue-400">Audit Swarm</span>
        </motion.h1>

        {/* Subline */}
        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="text-lg text-gray-400 mb-12 max-w-2xl leading-relaxed"
        >
          Paste any public GitHub repo URL. 9 AI agents find vulnerabilities, chain them into
          real attack paths, quantify your breach risk in dollars, and generate patches —
          in 4 minutes.{' '}
          <span className="text-blue-400 font-semibold">Free.</span>
        </motion.p>

        {/* Audit form */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="w-full max-w-2xl px-4"
        >
          <AuditForm />
        </motion.div>
      </section>

      {/* Stats */}
      <section className="max-w-5xl mx-auto px-4 pb-16">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-20">
          {STATS.map(({ icon: Icon, value, label }) => (
            <motion.div
              key={label}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="text-center p-6 rounded-xl border border-gray-700/60 bg-gray-900/40"
            >
              <Icon size={28} className="text-blue-400 mx-auto mb-3" />
              <div className="text-2xl font-bold text-white mb-1">{value}</div>
              <div className="text-sm text-gray-400">{label}</div>
            </motion.div>
          ))}
        </div>

        {/* Agents grid */}
        <h2 className="text-2xl font-bold text-center text-white mb-8">
          9 Specialised AI Agents
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {AGENTS.map(({ icon: Icon, name, color, desc }, i) => (
            <motion.div
              key={name}
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: i * 0.05 }}
              className="flex items-start gap-3 p-4 rounded-xl border border-gray-700/60 bg-gray-900/40
                hover:border-gray-600/80 transition-colors duration-200"
            >
              <div
                className="p-2 rounded-lg shrink-0"
                style={{ backgroundColor: color + '22', color }}
              >
                <Icon size={18} />
              </div>
              <div>
                <div className="text-sm font-semibold text-gray-200">{name}</div>
                <div className="text-xs text-gray-500 mt-0.5 leading-relaxed">{desc}</div>
              </div>
            </motion.div>
          ))}
        </div>

        {/* Innovation callout */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.6 }}
          className="mt-16 p-6 rounded-xl border border-red-800/40 bg-red-950/20 text-center"
        >
          <Zap size={28} className="text-red-400 mx-auto mb-3" />
          <h3 className="text-xl font-bold text-white mb-2">
            The Core Innovation: Attack Chain Synthesis
          </h3>
          <p className="text-sm text-gray-400 max-w-2xl mx-auto leading-relaxed">
            No existing tool connects isolated findings across layers.{' '}
            <span className="text-red-400">SwarmAudit</span> correlates code vulnerabilities,
            dependency CVEs, exposed secrets, and API gaps into complete exploit paths —
            like &ldquo;lodash CVE → bypass auth → SQLi → database takeover.&rdquo;
          </p>
        </motion.div>
      </section>

      {/* Footer */}
      <footer className="text-center py-8 text-xs text-gray-600 border-t border-gray-800">
        SwarmAudit — Built on Groq + Llama 3.1 70B · Semgrep · Neon.tech · Vercel · Render.com
        &nbsp;·&nbsp; For authorized security testing only.
      </footer>
    </main>
  );
}
