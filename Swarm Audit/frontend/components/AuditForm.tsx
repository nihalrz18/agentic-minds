'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Shield } from 'lucide-react';
import { motion } from 'framer-motion';
import { toast } from 'sonner';
import { startAudit } from '../lib/api';

export default function AuditForm() {
  const router  = useRouter();
  const [url, setUrl]       = useState('');
  const [loading, setLoading] = useState(false);

  const validate = (value: string): string | null => {
    if (!value.trim()) return 'Please enter a GitHub URL';
    if (!value.startsWith('https://github.com/'))
      return 'URL must start with https://github.com/';
    const parts = value.replace('https://github.com/', '').split('/');
    if (parts.length < 2 || !parts[0] || !parts[1])
      return 'URL must be in format: https://github.com/owner/repo';
    return null;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const err = validate(url);
    if (err) { toast.error(err); return; }

    setLoading(true);
    try {
      const { session_id } = await startAudit(url.trim());
      router.push(`/audit/${session_id}?url=${encodeURIComponent(url.trim())}`);
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : 'Failed to start audit';
      toast.error(msg);
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-2xl mx-auto">
      <div className="relative flex items-center gap-3">
        {/* Input with icon */}
        <div className="relative flex-1">
          <Shield
            size={18}
            className="absolute left-4 top-1/2 -translate-y-1/2 text-blue-400 pointer-events-none"
          />
          <input
            type="url"
            value={url}
            onChange={e => setUrl(e.target.value)}
            placeholder="https://github.com/owner/repo"
            disabled={loading}
            className="w-full pl-11 pr-4 py-4 rounded-xl border border-gray-700 bg-gray-900/80
              text-gray-100 placeholder-gray-500 text-base
              focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/50
              disabled:opacity-50 disabled:cursor-not-allowed
              transition-all duration-200"
            autoComplete="off"
            spellCheck={false}
          />
        </div>

        {/* Submit button */}
        <motion.button
          type="submit"
          disabled={loading}
          whileTap={{ scale: 0.97 }}
          className="shrink-0 px-8 py-4 rounded-xl bg-blue-600 hover:bg-blue-500
            text-white font-semibold text-base transition-colors duration-200
            disabled:opacity-60 disabled:cursor-not-allowed
            flex items-center gap-2"
        >
          {loading ? (
            <>
              <span className="h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Starting…
            </>
          ) : (
            'Start Audit →'
          )}
        </motion.button>
      </div>
      <p className="text-center text-xs text-gray-500 mt-3">
        Public repositories only • Free • No account required
      </p>
    </form>
  );
}
