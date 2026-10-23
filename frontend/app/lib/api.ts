// Frontend API client with safe error handling and real backend connectivity

export const apiBase = (): string => {
  if (typeof window !== "undefined") {
    // In browser: use relative URL so Next.js proxy rewrites handle backend requests without CORS or PNA issues
    return process.env.NEXT_PUBLIC_API_URL || "";
  }
  return process.env.API_URL || "http://127.0.0.1:8000";
};

export interface DashboardSummary {

  total_events: number;
  allowed_actions: number;
  blocked_actions: number;
  prompt_flags: number;
  active_incidents: number;
  critical_incidents: number;
  registered_agents: number;
  dlp_findings_detected: number;
  policy_mode: string;
  gateway_version: string;
  environment: string;
}

export interface SecurityEvent {
  id: number;
  event_id: string;
  timestamp: string;
  correlation_id: string;
  agent_id: string;
  tenant_id: string;
  tool: string;
  operation: string;
  resource: string | null;
  destination: string;
  decision: "ALLOW" | "BLOCK";
  reason: string;
  policy_version: string;
  policy_source: string;
  risk_level: string;
  prompt_flagged: boolean;
  dlp_findings: string[];
  metadata: Record<string, any>;
  execution_duration_ms: number | null;
  tamper_chain_hash: string;
}

export interface AgentRecord {
  id: string;
  name: string;
  tenant_id: string;
  description: string;
  status: "ACTIVE" | "SUSPENDED" | "REVOKED";
  allowed_tools: string[];
  scopes: string[];
  created_at: string | null;
}

export interface IncidentRecord {
  id: string;
  title: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  status: "OPEN" | "INVESTIGATING" | "RESOLVED" | "FALSE_POSITIVE";
  agent_id: string;
  tenant_id: string;
  rule_name: string;
  description: string;
  evidence_event_ids: string[];
  remediation_guidance: string;
  analyst_notes: string | null;
  assigned_to: string | null;
  created_at: string;
}

export interface PolicyRecord {
  id: string;
  name: string;
  version: string;
  checksum: string;
  is_active: boolean;
  rego_code: string;
}

export interface HashChainVerification {
  valid: boolean;
  total_events_verified?: number;
  head_hash?: string;
  error?: string;
  event_id?: string;
  tamper_evident?: boolean;
}

export async function fetchSummary(): Promise<DashboardSummary> {
  const res = await fetch(`${apiBase()}/api/v1/dashboard/summary`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Summary fetch failed (${res.status})`);
  return res.json();
}

export async function fetchEvents(limit = 50): Promise<SecurityEvent[]> {
  const res = await fetch(`${apiBase()}/api/v1/audit/events?limit=${limit}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Events fetch failed (${res.status})`);
  const data = await res.json();
  return data.events || [];
}

export async function fetchAgents(): Promise<AgentRecord[]> {
  const res = await fetch(`${apiBase()}/api/v1/agents`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Agents fetch failed (${res.status})`);
  return res.json();
}

export async function fetchIncidents(): Promise<IncidentRecord[]> {
  const res = await fetch(`${apiBase()}/api/v1/incidents`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Incidents fetch failed (${res.status})`);
  return res.json();
}

export async function fetchPolicies(): Promise<PolicyRecord[]> {
  const res = await fetch(`${apiBase()}/api/v1/policies`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Policies fetch failed (${res.status})`);
  return res.json();
}

export async function verifyAuditChain(): Promise<HashChainVerification> {
  const res = await fetch(`${apiBase()}/api/v1/audit/verify`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Audit verification failed (${res.status})`);
  return res.json();
}

export async function triggerDemoPrompt(prompt: string): Promise<any> {
  const res = await fetch(`${apiBase()}/api/v1/agents/demo-agent/prompt`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ prompt, tenant_id: "tenant-alpha" }),
  });
  const body = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, body };
}

export async function triggerDlpTest(text: string): Promise<any> {
  const res = await fetch(`${apiBase()}/api/v1/security/dlp`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text, action: "REDACT" }),
  });
  return res.json();
}

export async function updateIncidentStatus(id: string, status: string): Promise<any> {
  const res = await fetch(`${apiBase()}/api/v1/incidents/${id}/status`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
  });
  return res.json();
}

export async function addIncidentNote(id: string, notes: string): Promise<any> {
  const res = await fetch(`${apiBase()}/api/v1/incidents/${id}/notes`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ notes }),
  });
  return res.json();
}

export function getSSEStreamUrl(): string {
  return `${apiBase()}/api/v1/dashboard/events/stream`;
}

export interface PostureCheckResult {
  check_id: string;
  name: string;
  category: "MODEL_ENDPOINTS" | "IAM_IDENTITY" | "STORAGE_VECTOR_DB" | "NETWORK_EGRESS" | "CONTAINER_K8S" | "SUPPLY_CHAIN_AI" | "AUDIT_GOVERNANCE";
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  status: "PASS" | "FAIL" | "WARN";
  description: string;
  resource_id: string;
  compliance_frameworks: string[];
  remediation_command: string;
  remediation_guidance: string;
  evidence?: Record<string, any>;
}

export interface CSPMScanSummary {
  scan_id: string;
  timestamp: string;
  cloud_environment: string;
  compliance_score: number;
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  warning_checks: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  category_scores: Record<string, number>;
  findings: PostureCheckResult[];
}

export async function fetchCSPMSummary(): Promise<CSPMScanSummary> {
  const res = await fetch(`${apiBase()}/api/v1/cspm/summary`, { cache: "no-store" });
  if (!res.ok) throw new Error(`CSPM summary fetch failed (${res.status})`);
  return res.json();
}

export async function triggerCSPMScan(cloudEnvironment = "AWS / EKS Production"): Promise<CSPMScanSummary> {
  const res = await fetch(`${apiBase()}/api/v1/cspm/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cloud_environment: cloudEnvironment }),
  });
  if (!res.ok) throw new Error(`CSPM scan trigger failed (${res.status})`);
  return res.json();
}

export async function fetchCSPMFindings(status?: string, severity?: string): Promise<PostureCheckResult[]> {
  const params = new URLSearchParams();
  if (status) params.append("status", status);
  if (severity) params.append("severity", severity);
  const url = `${apiBase()}/api/v1/cspm/findings${params.toString() ? `?${params.toString()}` : ""}`;
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`CSPM findings fetch failed (${res.status})`);
  return res.json();
}

export async function fetchCSPMHistory(limit = 10): Promise<any[]> {
  const res = await fetch(`${apiBase()}/api/v1/cspm/history?limit=${limit}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`CSPM history fetch failed (${res.status})`);
  return res.json();
}


