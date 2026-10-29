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

// ==========================================
// LLM PROXY & STREAMING TYPES & CLIENT
// ==========================================

export interface ProviderInfo {
  id: string;
  name: string;
  available: boolean;
  requires_api_key: boolean;
  has_api_key: boolean;
  recommended_model: string;
  supported_models: string[];
  supports_streaming: boolean;
  supports_tools: boolean;
}

export interface ChatMessage {
  role: "system" | "user" | "assistant" | "tool";
  content?: string;
  name?: string;
  tool_calls?: any[];
}

export interface ToolExecutionTrace {
  tool_call_id: string;
  tool: string;
  operation: string;
  destination: string;
  args: Record<string, any>;
  decision: "ALLOW" | "BLOCK";
  status_code: number;
  result?: any;
  dlp_redacted: boolean;
  audit_event_id?: string;
  error?: string;
}

export interface ChatSecurityMetadata {
  prompt_scan_passed: boolean;
  input_dlp_redacted: boolean;
  output_dlp_redacted: boolean;
  canary_token_verified: boolean;
  audit_event_id?: string;
  correlation_id?: string;
  policy_evaluation_ms: number;
  tools_mediated_count: number;
}

export interface ChatCompletionResponse {
  id: string;
  provider: string;
  model: string;
  message: ChatMessage;
  finish_reason: string;
  security: ChatSecurityMetadata;
  tool_executions: ToolExecutionTrace[];
}

export async function fetchLLMProviders(): Promise<ProviderInfo[]> {
  const res = await fetch(`${apiBase()}/api/v1/llm/providers`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to fetch LLM providers (${res.status})`);
  return res.json();
}

export async function sendChatMessage(payload: {
  messages: ChatMessage[];
  provider?: string;
  model?: string;
  temperature?: number;
  max_tokens?: number;
  tenant_id?: string;
  agent_id?: string;
  tools_enabled?: boolean;
}): Promise<ChatCompletionResponse> {
  const res = await fetch(`${apiBase()}/api/v1/llm/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...payload, stream: false }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail?.error || err.detail?.reason || `Chat failed (${res.status})`);
  }
  return res.json();
}

// ==========================================
// MODEL CONTEXT PROTOCOL (MCP) GATEWAY
// ==========================================

export interface MCPToolSchema {
  name: string;
  description: string;
  inputSchema: Record<string, any>;
  zero_trust_policy: Record<string, any>;
}

export async function fetchMCPTools(): Promise<MCPToolSchema[]> {
  const res = await fetch(`${apiBase()}/api/v1/mcp/tools`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to fetch MCP tools (${res.status})`);
  return res.json();
}

export async function testMCPTool(payload: {
  tool_name: string;
  arguments: Record<string, any>;
  agent_id?: string;
  tenant_id?: string;
}): Promise<any> {
  const res = await fetch(`${apiBase()}/api/v1/mcp/test-call`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  return res.json();
}

// ==========================================
// ATTACK STUDIO & SIMULATOR
// ==========================================

export interface PipelineStepTrace {
  step_number: number;
  name: string;
  status: "PASSED" | "BLOCKED" | "SKIPPED";
  details: string;
  latency_ms: number;
}

export interface AttackScenario {
  id: string;
  name: string;
  category: string;
  threat_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  description: string;
  attack_vector: string;
  prompt?: string;
  tool_call?: Record<string, any>;
  expected_decision: string;
  expected_blocked_step: number;
  expected_blocked_step_name: string;
}

export interface AttackExecutionResult {
  scenario_id: string;
  name: string;
  category: string;
  threat_level: string;
  decision: "ALLOW" | "BLOCK";
  status_code: number;
  blocked_step?: number;
  blocked_step_name?: string;
  reason: string;
  duration_ms: number;
  pipeline_trace: PipelineStepTrace[];
  audit_event_id?: string;
  remediation_guidance: string;
}

export async function fetchAttackScenarios(): Promise<AttackScenario[]> {
  const res = await fetch(`${apiBase()}/api/v1/simulator/scenarios`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to fetch scenarios (${res.status})`);
  return res.json();
}

export async function runAttackSimulation(scenario_id: string): Promise<AttackExecutionResult> {
  const res = await fetch(`${apiBase()}/api/v1/simulator/run/${scenario_id}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail?.error || `Attack run failed (${res.status})`);
  }
  return res.json();
}

export async function runCustomAttackSimulation(payload: {
  name?: string;
  prompt?: string;
  tool_call?: Record<string, any>;
  tenant_id?: string;
}): Promise<AttackExecutionResult> {
  const res = await fetch(`${apiBase()}/api/v1/simulator/custom`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail?.error || `Custom attack failed (${res.status})`);
  }
  return res.json();
}


// ==========================================
// AI-CSPM PLATFORM API CLIENT
// ==========================================

export interface CSPMOverview {
  total_agents: number;
  total_environments: number;
  total_assets: number;
  total_open_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  agents_with_issues: number;
  recent_scan_count: number;
  average_risk_score: number;
  agent_health_summary: Record<string, number>;
  severity_distribution: Record<string, number>;
  category_distribution: Record<string, number>;
  recent_events: any[];
  is_demo_data: boolean;
}

export interface CSPMAgentRecord {
  id: string;
  name: string;
  tenant_id: string;
  environment_id: string | null;
  cloud_provider: string | null;
  cloud_account_id: string | null;
  deployment_environment: string;
  region: string | null;
  framework: string | null;
  model_provider: string | null;
  model_name: string | null;
  description: string | null;
  tools: string[];
  mcp_servers: string[];
  registration_source: string;
  status: string;
  connection_status: string;
  risk_score: number;
  open_findings_count: number;
  critical_findings_count: number;
  high_findings_count: number;
  last_seen_at: string | null;
  last_scan_at: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface CloudEnvironmentRecord {
  id: string;
  tenant_id: string;
  provider: string;
  account_id: string | null;
  name: string;
  description: string | null;
  region: string | null;
  connection_status: string;
  last_sync_at: string | null;
  health_status: string;
  connector_version: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface SecurityFindingRecord {
  id: string;
  rule_id: string | null;
  tenant_id: string;
  agent_id: string | null;
  environment_id: string | null;
  resource_id: string | null;
  title: string;
  description: string;
  category: string;
  severity: string;
  confidence: string;
  cloud_provider: string | null;
  detection_source: string | null;
  evidence: Record<string, any>;
  technical_detail: string | null;
  impact: string | null;
  remediation: string | null;
  compliance_frameworks: string[];
  status: string;
  first_seen_at: string | null;
  last_seen_at: string | null;
  resolved_at: string | null;
  created_at: string | null;
  updated_at: string | null;
  history?: FindingHistoryEntry[];
}

export interface FindingHistoryEntry {
  id: number;
  finding_id: string;
  previous_status: string | null;
  new_status: string;
  changed_by: string | null;
  notes: string | null;
  timestamp: string | null;
}

export interface ScanJobRecord {
  id: string;
  tenant_id: string;
  target_agent_id: string | null;
  target_environment_id: string | null;
  scan_type: string;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  warning_checks: number;
  findings_count: number;
  severity_distribution: Record<string, number>;
  coverage: Record<string, any>;
  error_detail: string | null;
  created_at: string | null;
}

export interface CSPMRuleRecord {
  id: string;
  name: string;
  category: string;
  severity: string;
  description: string;
  detection_logic_status: string;
  framework_mapping: string[];
  version: string;
  is_active: boolean;
  last_validated_at: string | null;
  last_validation_status: string | null;
  created_at: string | null;
  updated_at: string | null;
}

// --- CSPM Platform Fetchers ---

export async function fetchCSPMOverview(): Promise<CSPMOverview> {
  const res = await fetch(`${apiBase()}/api/v1/cspm/platform/overview`, { cache: "no-store" });
  if (!res.ok) throw new Error(`CSPM overview failed (${res.status})`);
  return res.json();
}

export async function fetchCSPMAgents(): Promise<CSPMAgentRecord[]> {
  const res = await fetch(`${apiBase()}/api/v1/cspm/platform/agents`, { cache: "no-store" });
  if (!res.ok) throw new Error(`CSPM agents failed (${res.status})`);
  return res.json();
}

export async function fetchCSPMAgent(agentId: string): Promise<CSPMAgentRecord> {
  const res = await fetch(`${apiBase()}/api/v1/cspm/platform/agents/${agentId}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`CSPM agent fetch failed (${res.status})`);
  return res.json();
}

export async function fetchCloudEnvironments(): Promise<CloudEnvironmentRecord[]> {
  const res = await fetch(`${apiBase()}/api/v1/cspm/platform/environments`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Environments fetch failed (${res.status})`);
  return res.json();
}

export async function fetchSecurityFindings(params?: {
  severity?: string; status?: string; category?: string;
  agent_id?: string; provider?: string; limit?: number; offset?: number;
}): Promise<{ findings: SecurityFindingRecord[]; total: number }> {
  const p = new URLSearchParams();
  if (params?.severity) p.append("severity", params.severity);
  if (params?.status) p.append("status", params.status);
  if (params?.category) p.append("category", params.category);
  if (params?.agent_id) p.append("agent_id", params.agent_id);
  if (params?.provider) p.append("provider", params.provider);
  if (params?.limit) p.append("limit", String(params.limit));
  if (params?.offset) p.append("offset", String(params.offset));
  const url = `${apiBase()}/api/v1/cspm/platform/findings${p.toString() ? `?${p}` : ""}`;
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`Findings fetch failed (${res.status})`);
  return res.json();
}

export async function fetchFindingDetail(findingId: string): Promise<SecurityFindingRecord> {
  const res = await fetch(`${apiBase()}/api/v1/cspm/platform/findings/${findingId}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Finding detail failed (${res.status})`);
  return res.json();
}

export async function updateFindingStatus(findingId: string, status: string, notes?: string): Promise<any> {
  const res = await fetch(`${apiBase()}/api/v1/cspm/platform/findings/${findingId}/status`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status, notes }),
  });
  if (!res.ok) throw new Error(`Status update failed (${res.status})`);
  return res.json();
}

export async function fetchScanJobs(): Promise<{ scans: ScanJobRecord[]; total: number }> {
  const res = await fetch(`${apiBase()}/api/v1/cspm/platform/scans`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Scans fetch failed (${res.status})`);
  return res.json();
}

export async function fetchCSPMRules(): Promise<CSPMRuleRecord[]> {
  const res = await fetch(`${apiBase()}/api/v1/cspm/platform/rules`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Rules fetch failed (${res.status})`);
  return res.json();
}

export async function registerCSPMAgent(payload: {
  name: string; cloud_provider?: string; deployment_environment?: string;
  region?: string; framework?: string; model_provider?: string;
  model_name?: string; description?: string;
}): Promise<CSPMAgentRecord> {
  const res = await fetch(`${apiBase()}/api/v1/cspm/platform/agents/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`Agent registration failed (${res.status})`);
  return res.json();
}
