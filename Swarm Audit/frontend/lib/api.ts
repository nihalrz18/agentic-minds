const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

export interface AuditStartResponse {
  session_id: string;
  status: string;
}

export interface AuditStatus {
  id: string;
  github_url: string;
  status: string;
  total_vulnerabilities: number | null;
  critical_count: number | null;
  high_count: number | null;
  medium_count: number | null;
  low_count: number | null;
  total_risk_usd: string | null;
  repo_name: string | null;
  tech_stack: string[] | null;
  file_count: number | null;
  created_at: string;
  completed_at: string | null;
}

class ApiError extends Error {
  constructor(public readonly statusCode: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      detail = body.detail ?? detail;
    } catch {
      // ignore
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

/**
 * Start a new audit session.
 * @param githubUrl  Public GitHub repository URL.
 */
export async function startAudit(githubUrl: string): Promise<AuditStartResponse> {
  return apiFetch<AuditStartResponse>('/api/audit/start', {
    method: 'POST',
    body: JSON.stringify({ github_url: githubUrl }),
  });
}

/**
 * Poll session status from the database.
 */
export async function getStatus(sessionId: string): Promise<AuditStatus> {
  return apiFetch<AuditStatus>(`/api/audit/${sessionId}/status`);
}

/**
 * Return the PDF download URL for a completed session.
 */
export function getReportUrl(sessionId: string): string {
  return `${API_BASE}/api/report/${sessionId}/download`;
}

// ── Direction A — new typed interfaces ─────────────────────────────────────

export type ValidationVerdict = 'VERIFIED' | 'UNVERIFIED' | 'INCONCLUSIVE' | 'SKIPPED';

export interface ValidationEvidence {
  vuln_id: string;
  verdict: ValidationVerdict;
  method: string;
  container_image: string;
  command_executed: string;
  exit_code: number | null;
  stdout_excerpt: string;
  stderr_excerpt: string;
  timeout_hit: boolean;
  duration_ms: number;
  notes: string;
}

export interface ValidationResponse {
  session_id: string;
  validation_results: ValidationEvidence[];
}

export interface ComplianceMapping {
  vuln_id: string;
  framework: string;
  control_id: string;
  control_name: string;
  owasp_category: string;
  rationale: string;
}

export interface BlastRadius {
  framework_counts: Record<string, number>;
  top_high_risk_controls: { framework: string; control_id: string; control_name: string }[];
  total_controls_at_risk: number;
}

export interface ComplianceResponse {
  session_id: string;
  compliance_mappings: ComplianceMapping[];
  blast_radius: BlastRadius;
}

export interface ReportLinkResponse {
  session_id: string;
  status: string;
  report_url: string;
  pdf_url: string;
}

/**
 * Fetch sandbox validation results for a session.
 */
export async function getValidationResults(sessionId: string): Promise<ValidationResponse> {
  return apiFetch<ValidationResponse>(`/api/audit/${sessionId}/validation`);
}

/**
 * Fetch compliance mappings and blast radius for a session.
 */
export async function getComplianceMappings(sessionId: string): Promise<ComplianceResponse> {
  return apiFetch<ComplianceResponse>(`/api/audit/${sessionId}/compliance`);
}

/**
 * Fetch the deep-link report URL for a session.
 */
export async function getReportLink(sessionId: string): Promise<ReportLinkResponse> {
  return apiFetch<ReportLinkResponse>(`/api/audit/${sessionId}/report-link`);
}

/**
 * Start a PR-scoped audit scan (called from GitHub Actions via internal API key).
 */
export async function startPRScan(
  params: {
    github_url: string;
    repo_full_name: string;
    pr_number: number;
    sha: string;
    changed_files: string[];
  },
  internalApiKey: string,
): Promise<AuditStartResponse> {
  return apiFetch<AuditStartResponse>('/api/audit/start-pr-scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': internalApiKey,
    },
    body: JSON.stringify(params),
  });
}
