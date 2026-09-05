import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { Toaster } from 'sonner';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title:       'SwarmAudit — Autonomous Security Audit Swarm',
  description:
    '9 AI agents find vulnerabilities, chain them into real attack paths, '
    + 'quantify breach risk in dollars, and generate patches — automatically.',
  keywords:    ['security audit', 'SAST', 'penetration testing', 'AI agents', 'vulnerability scanner'],
  openGraph: {
    title:       'SwarmAudit — Autonomous Security Audit Swarm',
    description: 'Paste a GitHub URL. Get a full pentest report in 4 minutes. Free.',
    type:        'website',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-[#0d1117] text-gray-100 min-h-screen`}>
        {children}
        <Toaster
          theme="dark"
          position="top-right"
          toastOptions={{
            style: {
              background: '#161b22',
              border:     '1px solid #30363d',
              color:      '#c9d1d9',
            },
          }}
        />
      </body>
    </html>
  );
}
