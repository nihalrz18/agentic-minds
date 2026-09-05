'use client';

import { motion } from 'framer-motion';
import { Download, FileText, Loader2, CheckCircle } from 'lucide-react';
import { getReportUrl } from '../lib/api';

interface ReportViewerProps {
  sessionId:   string;
  reportReady: boolean;
  totalVulns?: number;
  totalRisk?:  number;
}

export default function ReportViewer({ sessionId, reportReady, totalVulns, totalRisk }: ReportViewerProps) {
  const reportUrl = getReportUrl(sessionId);

  return (
    <div className="rounded-lg border border-gray-700/60 bg-gray-900/40 p-4 space-y-4">
      <div className="flex items-center gap-2">
        <FileText size={18} className="text-blue-400" />
        <h3 className="text-sm font-semibold text-gray-200">Full Pentest Report</h3>
      </div>

      {reportReady ? (
        <>
          <div className="flex items-center gap-2 text-green-400 text-sm">
            <CheckCircle size={16} />
            <span>PDF report generated successfully</span>
          </div>

          {(totalVulns !== undefined || totalRisk !== undefined) && (
            <div className="grid grid-cols-2 gap-3 text-xs">
              {totalVulns !== undefined && (
                <div className="bg-gray-800/60 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-gray-200">{totalVulns}</div>
                  <div className="text-gray-500 mt-0.5">Total Findings</div>
                </div>
              )}
              {totalRisk !== undefined && totalRisk > 0 && (
                <div className="bg-gray-800/60 rounded-lg p-3 text-center">
                  <div className="text-2xl font-bold text-red-400">
                    ${(totalRisk / 1000).toFixed(0)}K
                  </div>
                  <div className="text-gray-500 mt-0.5">Breach Exposure</div>
                </div>
              )}
            </div>
          )}

          <motion.a
            href={reportUrl}
            target="_blank"
            rel="noopener noreferrer"
            whileTap={{ scale: 0.97 }}
            className="flex items-center justify-center gap-2 w-full py-3 rounded-lg
              bg-blue-600 hover:bg-blue-500 text-white font-semibold text-sm
              transition-colors duration-200"
          >
            <Download size={16} />
            📥 Download Full PDF Report
          </motion.a>
        </>
      ) : (
        <div className="flex items-center gap-3 text-sm text-gray-400 py-2">
          <Loader2 size={16} className="animate-spin text-blue-400" />
          <span>Generating report… (available when audit completes)</span>
        </div>
      )}
    </div>
  );
}
