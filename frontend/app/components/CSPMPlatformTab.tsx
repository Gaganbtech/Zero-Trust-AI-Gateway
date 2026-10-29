"use client";
import React, { useState, useEffect } from "react";
import {
  Shield, AlertTriangle, Server, Cloud, Search, Filter, ChevronDown,
  ChevronRight, Clock, Activity, ArrowUpRight, ExternalLink, CheckCircle2,
  XCircle, AlertCircle, Info, Cpu, Globe, Eye, Wifi, WifiOff, Layers,
  BarChart3, TrendingUp, BookOpen, RefreshCw, Loader2
} from "lucide-react";
import {
  fetchCSPMOverview, fetchCSPMAgents, fetchCloudEnvironments,
  fetchSecurityFindings, fetchFindingDetail, updateFindingStatus,
  fetchScanJobs, fetchCSPMRules,
  CSPMOverview, CSPMAgentRecord, CloudEnvironmentRecord,
  SecurityFindingRecord, ScanJobRecord, CSPMRuleRecord,
} from "../lib/api";

type SubView = "overview" | "agents" | "findings" | "scans" | "environments" | "rules";

interface PlatformTabProps { onRefresh: () => void; }

const SEV_COLORS: Record<string, string> = {
  CRITICAL: "bg-red-950 text-red-400 border-red-800/60",
  HIGH: "bg-orange-950 text-orange-400 border-orange-800/60",
  MEDIUM: "bg-yellow-950 text-yellow-400 border-yellow-800/60",
  LOW: "bg-blue-950 text-blue-400 border-blue-800/60",
  INFO: "bg-slate-800 text-slate-300 border-slate-700",
};

const STATUS_COLORS: Record<string, string> = {
  OPEN: "bg-red-950 text-red-400 border-red-800/60",
  ACKNOWLEDGED: "bg-yellow-950 text-yellow-400 border-yellow-800/60",
  IN_PROGRESS: "bg-cyan-950 text-cyan-400 border-cyan-800/60",
  RESOLVED: "bg-emerald-950 text-emerald-400 border-emerald-800/60",
  FALSE_POSITIVE: "bg-slate-800 text-slate-400 border-slate-700",
};

const PROVIDER_ICONS: Record<string, string> = { AWS: "☁️", AZURE: "🔷", GCP: "🟡" };

function Badge({ text, colors }: { text: string; colors: string }) {
  return <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase border ${colors}`}>{text}</span>;
}

function StatCard({ label, value, icon: Icon, accent = "text-cyan-400" }: { label: string; value: number | string; icon: any; accent?: string }) {
  return (
    <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-slate-400 font-medium">{label}</span>
        <Icon className={`w-4 h-4 ${accent}`} />
      </div>
      <div className={`text-2xl font-bold font-mono ${accent}`}>{value}</div>
    </div>
  );
}

function timeAgo(iso: string | null): string {
  if (!iso) return "Never";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

// ============================================================
// OVERVIEW SUB-VIEW
// ============================================================
function OverviewSection({ overview, agents, findings, onNavigate }: {
  overview: CSPMOverview | null; agents: CSPMAgentRecord[]; findings: SecurityFindingRecord[];
  onNavigate: (v: SubView) => void;
}) {
  if (!overview) return <div className="text-slate-400 text-center py-12"><Loader2 className="w-6 h-6 animate-spin mx-auto mb-2" />Loading platform overview...</div>;
  return (
    <div className="space-y-6">
      {overview.is_demo_data && (
        <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-amber-950/40 border border-amber-800/40 text-amber-300 text-xs">
          <Info className="w-4 h-4 flex-shrink-0" />
          <span><strong>Demonstration Mode</strong> — Platform is displaying seeded sample data. Connect real AI agents in Phase 2 to replace with live security posture.</span>
        </div>
      )}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        <StatCard label="AI Agents" value={overview.total_agents} icon={Cpu} />
        <StatCard label="Cloud Environments" value={overview.total_environments} icon={Cloud} />
        <StatCard label="Open Findings" value={overview.total_open_findings} icon={AlertTriangle} accent="text-orange-400" />
        <StatCard label="Critical" value={overview.critical_findings} icon={XCircle} accent="text-red-400" />
        <StatCard label="High" value={overview.high_findings} icon={AlertCircle} accent="text-orange-400" />
        <StatCard label="Avg Risk Score" value={overview.average_risk_score.toFixed(1)} icon={TrendingUp} accent={overview.average_risk_score > 60 ? "text-red-400" : overview.average_risk_score > 30 ? "text-yellow-400" : "text-emerald-400"} />
      </div>

      {/* Severity Distribution */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
          <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2"><BarChart3 className="w-4 h-4 text-cyan-400" />Severity Distribution</h4>
          <div className="space-y-2">
            {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => {
              const count = overview.severity_distribution[s] || 0;
              const maxCount = Math.max(...Object.values(overview.severity_distribution), 1);
              const pct = (count / maxCount) * 100;
              const barColor = s === "CRITICAL" ? "bg-red-500" : s === "HIGH" ? "bg-orange-500" : s === "MEDIUM" ? "bg-yellow-500" : "bg-blue-500";
              return (
                <div key={s} className="flex items-center gap-3">
                  <span className="text-xs font-mono text-slate-400 w-16">{s}</span>
                  <div className="flex-1 h-4 bg-slate-800 rounded-full overflow-hidden"><div className={`h-full ${barColor} rounded-full transition-all duration-500`} style={{ width: `${pct}%` }} /></div>
                  <span className="text-xs font-mono text-white w-6 text-right">{count}</span>
                </div>
              );
            })}
          </div>
        </div>
        <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
          <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2"><Layers className="w-4 h-4 text-cyan-400" />Agent Health</h4>
          <div className="space-y-3">
            {agents.map(a => (
              <div key={a.id} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span className="text-sm">{PROVIDER_ICONS[a.cloud_provider || ""] || "🔲"}</span>
                  <span className="text-white font-medium">{a.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  {a.connection_status === "CONNECTED" ? <Wifi className="w-3 h-3 text-emerald-400" /> : <WifiOff className="w-3 h-3 text-slate-500" />}
                  <Badge text={a.connection_status} colors={a.connection_status === "CONNECTED" ? "bg-emerald-950 text-emerald-400 border-emerald-800/60" : "bg-slate-800 text-slate-400 border-slate-700"} />
                  {a.open_findings_count > 0 && <span className="text-orange-400 font-mono">{a.open_findings_count} findings</span>}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Critical/High Findings */}
      <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
        <div className="flex items-center justify-between mb-4">
          <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-orange-400" />Recent Critical & High Findings</h4>
          <button onClick={() => onNavigate("findings")} className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1">View All <ArrowUpRight className="w-3 h-3" /></button>
        </div>
        <div className="space-y-2">
          {findings.filter(f => f.severity === "CRITICAL" || f.severity === "HIGH").slice(0, 5).map(f => (
            <div key={f.id} className="flex items-center justify-between py-2 px-3 rounded-lg bg-slate-950/50 border border-slate-800/50 hover:border-slate-700 transition">
              <div className="flex items-center gap-3 flex-1 min-w-0">
                <Badge text={f.severity} colors={SEV_COLORS[f.severity]} />
                <span className="text-xs text-white truncate">{f.title}</span>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0 ml-3">
                {f.cloud_provider && <span className="text-sm">{PROVIDER_ICONS[f.cloud_provider] || ""}</span>}
                <Badge text={f.status} colors={STATUS_COLORS[f.status] || STATUS_COLORS.OPEN} />
              </div>
            </div>
          ))}
          {findings.filter(f => f.severity === "CRITICAL" || f.severity === "HIGH").length === 0 && (
            <p className="text-xs text-slate-500 text-center py-4">No critical or high-severity findings</p>
          )}
        </div>
      </div>
    </div>
  );
}

// ============================================================
// AGENTS SUB-VIEW
// ============================================================
function AgentsSection({ agents, onNavigate }: { agents: CSPMAgentRecord[]; onNavigate: (v: SubView) => void }) {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2"><Cpu className="w-4 h-4 text-cyan-400" />AI Agent Inventory ({agents.length})</h3>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {agents.map(a => (
          <div key={a.id} className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition space-y-3">
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-sm">{PROVIDER_ICONS[a.cloud_provider || ""] || "🔲"}</span>
                  <h4 className="text-sm font-bold text-white">{a.name}</h4>
                  <Badge text={a.status} colors={a.status === "ACTIVE" ? "bg-emerald-950 text-emerald-400 border-emerald-800/60" : "bg-red-950 text-red-400 border-red-800/60"} />
                </div>
                <p className="text-xs text-slate-400">{a.description}</p>
              </div>
              <div className="text-right flex-shrink-0 ml-3">
                <div className={`text-xl font-bold font-mono ${a.risk_score >= 60 ? "text-red-400" : a.risk_score >= 30 ? "text-yellow-400" : "text-emerald-400"}`}>{a.risk_score.toFixed(0)}</div>
                <div className="text-[10px] text-slate-500">RISK SCORE</div>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs font-mono border-t border-slate-800 pt-3">
              <div className="flex justify-between text-slate-400"><span>Provider:</span><span className="text-white">{a.cloud_provider || "—"}</span></div>
              <div className="flex justify-between text-slate-400"><span>Region:</span><span className="text-white">{a.region || "—"}</span></div>
              <div className="flex justify-between text-slate-400"><span>Framework:</span><span className="text-cyan-300">{a.framework || "—"}</span></div>
              <div className="flex justify-between text-slate-400"><span>Model:</span><span className="text-cyan-300">{a.model_name || "—"}</span></div>
              <div className="flex justify-between text-slate-400"><span>Environment:</span><span className="text-white">{a.deployment_environment}</span></div>
              <div className="flex justify-between text-slate-400"><span>Last Seen:</span><span className="text-white">{timeAgo(a.last_seen_at)}</span></div>
            </div>
            <div className="flex items-center justify-between border-t border-slate-800 pt-3">
              <div className="flex items-center gap-2">
                {a.connection_status === "CONNECTED" ? <Wifi className="w-3 h-3 text-emerald-400" /> : <WifiOff className="w-3 h-3 text-slate-500" />}
                <Badge text={a.connection_status} colors={a.connection_status === "CONNECTED" ? "bg-emerald-950 text-emerald-400 border-emerald-800/60" : "bg-slate-800 text-slate-400 border-slate-700"} />
              </div>
              <div className="flex items-center gap-3 text-xs font-mono">
                {a.critical_findings_count > 0 && <span className="text-red-400">{a.critical_findings_count} CRIT</span>}
                {a.high_findings_count > 0 && <span className="text-orange-400">{a.high_findings_count} HIGH</span>}
                <span className="text-slate-400">{a.open_findings_count} total open</span>
              </div>
            </div>
            {(a.tools.length > 0 || a.mcp_servers.length > 0) && (
              <div className="border-t border-slate-800 pt-3">
                {a.tools.length > 0 && (
                  <div className="mb-1.5"><span className="text-[10px] text-slate-500 uppercase">Tools: </span>{a.tools.map((t,i) => <span key={i} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-950 text-emerald-400 border border-slate-800 mr-1">{t}</span>)}</div>
                )}
                {a.mcp_servers.length > 0 && (
                  <div><span className="text-[10px] text-slate-500 uppercase">MCP Servers: </span>{a.mcp_servers.map((m,i) => <span key={i} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-950 text-purple-400 border border-slate-800 mr-1">{m}</span>)}</div>
                )}
              </div>
            )}
            {a.registration_source === "demo" && <div className="text-[10px] text-amber-500/80 flex items-center gap-1"><Info className="w-3 h-3" />Demonstration agent — not connected to real infrastructure</div>}
          </div>
        ))}
      </div>
    </div>
  );
}

// ============================================================
// FINDINGS SUB-VIEW
// ============================================================
function FindingsSection({ onRefresh }: { onRefresh: () => void }) {
  const [findings, setFindings] = useState<SecurityFindingRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState<{ severity?: string; status?: string; category?: string }>({});
  const [selectedFinding, setSelectedFinding] = useState<SecurityFindingRecord | null>(null);
  const [updatingStatus, setUpdatingStatus] = useState(false);

  const loadFindings = async () => {
    setLoading(true);
    try {
      const res = await fetchSecurityFindings({ ...filters, limit: 50 });
      setFindings(res.findings);
      setTotal(res.total);
    } catch { }
    setLoading(false);
  };

  useEffect(() => { loadFindings(); }, [filters]);

  const handleStatusUpdate = async (findingId: string, newStatus: string) => {
    setUpdatingStatus(true);
    try {
      await updateFindingStatus(findingId, newStatus, `Status changed to ${newStatus}`);
      // Reload detail
      const detail = await fetchFindingDetail(findingId);
      setSelectedFinding(detail);
      loadFindings();
      onRefresh();
    } catch { }
    setUpdatingStatus(false);
  };

  const SEVERITIES = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const STATUSES = ["", "OPEN", "ACKNOWLEDGED", "IN_PROGRESS", "RESOLVED"];
  const CATEGORIES = ["", "PROMPT_INJECTION", "JAILBREAK_RESISTANCE", "IAM_PERMISSIONS", "DATA_LEAKAGE",
    "NETWORK_SSRF", "MCP_TOOL_SECURITY", "CLOUD_CONFIG", "AGENT_CONFIG", "LOGGING_AUDIT",
    "CROSS_TENANT_ISOLATION", "VULNERABLE_DEPENDENCIES", "INSECURE_INTEGRATION"];

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-slate-400" />
          <select value={filters.severity || ""} onChange={e => setFilters(f => ({ ...f, severity: e.target.value || undefined }))} className="text-xs bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-white">
            <option value="">All Severities</option>
            {SEVERITIES.filter(Boolean).map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={filters.status || ""} onChange={e => setFilters(f => ({ ...f, status: e.target.value || undefined }))} className="text-xs bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-white">
            <option value="">All Statuses</option>
            {STATUSES.filter(Boolean).map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={filters.category || ""} onChange={e => setFilters(f => ({ ...f, category: e.target.value || undefined }))} className="text-xs bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-white">
            <option value="">All Categories</option>
            {CATEGORIES.filter(Boolean).map(c => <option key={c} value={c}>{c.replace(/_/g, " ")}</option>)}
          </select>
        </div>
        <span className="text-xs text-slate-500 ml-auto">{total} findings</span>
      </div>

      {loading ? (
        <div className="text-center py-8 text-slate-400"><Loader2 className="w-5 h-5 animate-spin mx-auto mb-2" />Loading findings...</div>
      ) : (
        <div className="space-y-2">
          {findings.map(f => (
            <div key={f.id} onClick={async () => { const d = await fetchFindingDetail(f.id).catch(() => f); setSelectedFinding(d); }} className="flex items-center gap-3 py-3 px-4 rounded-lg bg-slate-900/80 border border-slate-800/50 hover:border-slate-700 transition cursor-pointer group">
              <Badge text={f.severity} colors={SEV_COLORS[f.severity]} />
              <div className="flex-1 min-w-0">
                <div className="text-xs text-white font-medium truncate group-hover:text-cyan-300 transition">{f.title}</div>
                <div className="text-[10px] text-slate-500 mt-0.5 flex items-center gap-2">
                  <span>{f.category.replace(/_/g, " ")}</span>
                  {f.agent_id && <><span>•</span><span>{f.agent_id}</span></>}
                  {f.cloud_provider && <><span>•</span><span>{PROVIDER_ICONS[f.cloud_provider] || ""} {f.cloud_provider}</span></>}
                </div>
              </div>
              <Badge text={f.status} colors={STATUS_COLORS[f.status] || STATUS_COLORS.OPEN} />
              <span className="text-[10px] text-slate-500 font-mono w-14 text-right">{timeAgo(f.last_seen_at)}</span>
              <ChevronRight className="w-3 h-3 text-slate-600 group-hover:text-slate-400" />
            </div>
          ))}
          {findings.length === 0 && <p className="text-xs text-slate-500 text-center py-8">No findings match the selected filters</p>}
        </div>
      )}

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setSelectedFinding(null)}>
          <div className="bg-slate-900 border border-slate-700 rounded-2xl p-6 max-w-2xl w-full mx-4 max-h-[85vh] overflow-y-auto shadow-2xl" onClick={e => e.stopPropagation()}>
            <div className="flex items-start justify-between mb-4">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <Badge text={selectedFinding.severity} colors={SEV_COLORS[selectedFinding.severity]} />
                  <Badge text={selectedFinding.status} colors={STATUS_COLORS[selectedFinding.status] || STATUS_COLORS.OPEN} />
                  {selectedFinding.cloud_provider && <span className="text-sm">{PROVIDER_ICONS[selectedFinding.cloud_provider]}</span>}
                </div>
                <h3 className="text-base font-bold text-white">{selectedFinding.title}</h3>
                <div className="text-[10px] text-slate-500 font-mono mt-1">{selectedFinding.id} • Rule: {selectedFinding.rule_id || "—"}</div>
              </div>
              <button onClick={() => setSelectedFinding(null)} className="text-slate-400 hover:text-white text-lg">✕</button>
            </div>

            <div className="space-y-4 text-xs">
              <div><h5 className="font-semibold text-slate-300 mb-1">Description</h5><p className="text-slate-400 leading-relaxed">{selectedFinding.description}</p></div>
              {selectedFinding.technical_detail && <div><h5 className="font-semibold text-slate-300 mb-1">Technical Detail</h5><p className="text-slate-400 leading-relaxed">{selectedFinding.technical_detail}</p></div>}
              {selectedFinding.impact && <div><h5 className="font-semibold text-orange-300 mb-1">Potential Impact</h5><p className="text-slate-400 leading-relaxed">{selectedFinding.impact}</p></div>}
              {selectedFinding.remediation && <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-800/30"><h5 className="font-semibold text-emerald-300 mb-1">Recommended Remediation</h5><p className="text-emerald-200/80 leading-relaxed">{selectedFinding.remediation}</p></div>}

              {selectedFinding.evidence && Object.keys(selectedFinding.evidence).length > 0 && (
                <div><h5 className="font-semibold text-slate-300 mb-1">Evidence</h5>
                  <pre className="text-[10px] font-mono p-3 rounded bg-slate-950 border border-slate-800 overflow-x-auto text-slate-300">{JSON.stringify(selectedFinding.evidence, null, 2)}</pre>
                </div>
              )}

              {selectedFinding.compliance_frameworks?.length > 0 && (
                <div><h5 className="font-semibold text-slate-300 mb-1">Compliance Frameworks</h5>
                  <div className="flex flex-wrap gap-1">{selectedFinding.compliance_frameworks.map((fw, i) => <span key={i} className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-purple-300 border border-slate-800">{fw}</span>)}</div>
                </div>
              )}

              <div className="grid grid-cols-2 gap-2 font-mono text-[10px] border-t border-slate-800 pt-3">
                <div className="text-slate-500">Agent: <span className="text-white">{selectedFinding.agent_id || "—"}</span></div>
                <div className="text-slate-500">Resource: <span className="text-white">{selectedFinding.resource_id || "—"}</span></div>
                <div className="text-slate-500">First Seen: <span className="text-white">{selectedFinding.first_seen_at ? new Date(selectedFinding.first_seen_at).toLocaleString() : "—"}</span></div>
                <div className="text-slate-500">Last Seen: <span className="text-white">{selectedFinding.last_seen_at ? new Date(selectedFinding.last_seen_at).toLocaleString() : "—"}</span></div>
              </div>

              {/* Status Transition Controls */}
              <div className="border-t border-slate-800 pt-3">
                <h5 className="font-semibold text-slate-300 mb-2">Update Status</h5>
                <div className="flex flex-wrap gap-2">
                  {["OPEN", "ACKNOWLEDGED", "IN_PROGRESS", "RESOLVED"].map(s => (
                    <button key={s} disabled={selectedFinding.status === s || updatingStatus}
                      onClick={() => handleStatusUpdate(selectedFinding.id, s)}
                      className={`text-[10px] font-mono px-3 py-1.5 rounded border transition ${selectedFinding.status === s ? "opacity-40 cursor-not-allowed" : "hover:brightness-125 cursor-pointer"} ${STATUS_COLORS[s]}`}>
                      {updatingStatus ? <Loader2 className="w-3 h-3 animate-spin inline mr-1" /> : null}{s}
                    </button>
                  ))}
                </div>
              </div>

              {/* History */}
              {selectedFinding.history && selectedFinding.history.length > 0 && (
                <div className="border-t border-slate-800 pt-3">
                  <h5 className="font-semibold text-slate-300 mb-2">Status History</h5>
                  <div className="space-y-1.5">
                    {selectedFinding.history.map((h, i) => (
                      <div key={i} className="flex items-center gap-2 text-[10px] font-mono text-slate-400">
                        <Clock className="w-3 h-3" />
                        <span>{h.timestamp ? new Date(h.timestamp).toLocaleString() : "—"}</span>
                        <span>•</span>
                        {h.previous_status && <><Badge text={h.previous_status} colors={STATUS_COLORS[h.previous_status] || ""} /><span>→</span></>}
                        <Badge text={h.new_status} colors={STATUS_COLORS[h.new_status] || ""} />
                        {h.changed_by && <span className="text-slate-500">by {h.changed_by}</span>}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ============================================================
// ENVIRONMENTS SUB-VIEW
// ============================================================
function EnvironmentsSection({ environments }: { environments: CloudEnvironmentRecord[] }) {
  return (
    <div className="space-y-4">
      <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2"><Globe className="w-4 h-4 text-cyan-400" />Cloud Environments ({environments.length})</h3>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {environments.map(env => (
          <div key={env.id} className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-xl">{PROVIDER_ICONS[env.provider] || "☁️"}</span>
                <div>
                  <h4 className="text-sm font-bold text-white">{env.name}</h4>
                  <span className="text-[10px] text-slate-500 font-mono">{env.provider} • {env.region || "—"}</span>
                </div>
              </div>
              <Badge text={env.connection_status} colors={env.connection_status === "CONNECTED" ? "bg-emerald-950 text-emerald-400 border-emerald-800/60" : "bg-slate-800 text-slate-400 border-slate-700"} />
            </div>
            <p className="text-xs text-slate-400">{env.description}</p>
            <div className="grid grid-cols-2 gap-2 text-xs font-mono border-t border-slate-800 pt-3">
              <div className="text-slate-500">Account: <span className="text-white">{env.account_id || "—"}</span></div>
              <div className="text-slate-500">Health: <Badge text={env.health_status} colors={env.health_status === "HEALTHY" ? "bg-emerald-950 text-emerald-400 border-emerald-800/60" : "bg-slate-800 text-slate-400 border-slate-700"} /></div>
              <div className="text-slate-500">Last Sync: <span className="text-white">{timeAgo(env.last_sync_at)}</span></div>
              <div className="text-slate-500">Connector: <span className="text-white">{env.connector_version || "Not installed"}</span></div>
            </div>
            {env.connection_status === "NOT_CONNECTED" && (
              <div className="flex items-center gap-1.5 text-[10px] text-amber-500/80"><Info className="w-3 h-3" />Connector not yet configured — cloud integration available in Phase 2</div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ============================================================
// SCANS SUB-VIEW
// ============================================================
function ScansSection() {
  const [scans, setScans] = useState<ScanJobRecord[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => { fetchScanJobs().then(r => { setScans(r.scans); setLoading(false); }).catch(() => setLoading(false)); }, []);

  const SCAN_STATUS_COLORS: Record<string, string> = {
    COMPLETED: "bg-emerald-950 text-emerald-400 border-emerald-800/60",
    RUNNING: "bg-cyan-950 text-cyan-400 border-cyan-800/60",
    PENDING: "bg-yellow-950 text-yellow-400 border-yellow-800/60",
    FAILED: "bg-red-950 text-red-400 border-red-800/60",
  };

  if (loading) return <div className="text-center py-8 text-slate-400"><Loader2 className="w-5 h-5 animate-spin mx-auto mb-2" />Loading scan history...</div>;
  return (
    <div className="space-y-4">
      <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2"><Activity className="w-4 h-4 text-cyan-400" />Scan History ({scans.length})</h3>
      <div className="space-y-2">
        {scans.map(s => (
          <div key={s.id} className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-3">
                <Badge text={s.status} colors={SCAN_STATUS_COLORS[s.status] || SCAN_STATUS_COLORS.PENDING} />
                <span className="text-xs font-mono text-slate-300">{s.id}</span>
                <span className="text-[10px] font-mono text-cyan-400 px-2 py-0.5 rounded bg-slate-950 border border-slate-800">{s.scan_type.replace(/_/g, " ")}</span>
              </div>
              <span className="text-[10px] text-slate-500 font-mono">{s.started_at ? new Date(s.started_at).toLocaleString() : "—"}</span>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-2 text-xs font-mono mt-2">
              <div className="text-slate-500">Target: <span className="text-white">{s.target_agent_id || s.target_environment_id || "—"}</span></div>
              <div className="text-slate-500">Total: <span className="text-white">{s.total_checks}</span></div>
              <div className="text-emerald-400">Passed: {s.passed_checks}</div>
              <div className="text-red-400">Failed: {s.failed_checks}</div>
              <div className="text-orange-400">Findings: {s.findings_count}</div>
            </div>
            {s.severity_distribution && Object.keys(s.severity_distribution).length > 0 && (
              <div className="flex gap-2 mt-2">{Object.entries(s.severity_distribution).filter(([,v]) => v > 0).map(([k,v]) => <span key={k} className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${SEV_COLORS[k]}`}>{k}: {v}</span>)}</div>
            )}
            {s.error_detail && <div className="text-[10px] text-red-400 mt-2">{s.error_detail}</div>}
          </div>
        ))}
        {scans.length === 0 && <p className="text-xs text-slate-500 text-center py-8">No scan history available</p>}
      </div>
    </div>
  );
}

// ============================================================
// RULES SUB-VIEW
// ============================================================
function RulesSection() {
  const [rules, setRules] = useState<CSPMRuleRecord[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => { fetchCSPMRules().then(setRules).catch(() => {}).finally(() => setLoading(false)); }, []);

  const LOGIC_COLORS: Record<string, string> = {
    IMPLEMENTED: "bg-emerald-950 text-emerald-400 border-emerald-800/60",
    PARTIAL: "bg-yellow-950 text-yellow-400 border-yellow-800/60",
    NOT_IMPLEMENTED: "bg-slate-800 text-slate-400 border-slate-700",
  };

  if (loading) return <div className="text-center py-8 text-slate-400"><Loader2 className="w-5 h-5 animate-spin mx-auto" /></div>;
  return (
    <div className="space-y-4">
      <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2"><BookOpen className="w-4 h-4 text-cyan-400" />CSPM Security Rules ({rules.length})</h3>
      <div className="space-y-2">
        {rules.map(r => (
          <div key={r.id} className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition">
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-cyan-400">{r.id}</span>
                <Badge text={r.severity} colors={SEV_COLORS[r.severity]} />
                <Badge text={r.detection_logic_status.replace(/_/g, " ")} colors={LOGIC_COLORS[r.detection_logic_status] || LOGIC_COLORS.NOT_IMPLEMENTED} />
                {r.last_validation_status && <Badge text={`Last: ${r.last_validation_status}`} colors={r.last_validation_status === "PASS" ? "bg-emerald-950 text-emerald-400 border-emerald-800/60" : "bg-red-950 text-red-400 border-red-800/60"} />}
              </div>
              <span className="text-[10px] text-slate-500 font-mono">v{r.version}</span>
            </div>
            <h4 className="text-xs font-semibold text-white mb-1">{r.name}</h4>
            <p className="text-[10px] text-slate-400">{r.description}</p>
            <div className="flex items-center gap-2 mt-2">
              <span className="text-[10px] text-slate-500 uppercase">Category: </span>
              <span className="text-[10px] font-mono text-slate-300">{r.category.replace(/_/g, " ")}</span>
              {r.framework_mapping.length > 0 && (
                <>{r.framework_mapping.slice(0, 3).map((fw, i) => <span key={i} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-950 text-purple-300 border border-slate-800">{fw}</span>)}</>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ============================================================
// MAIN PLATFORM TAB COMPONENT
// ============================================================
export const CSPMPlatformTab: React.FC<PlatformTabProps> = ({ onRefresh }) => {
  const [subView, setSubView] = useState<SubView>("overview");
  const [overview, setOverview] = useState<CSPMOverview | null>(null);
  const [agents, setAgents] = useState<CSPMAgentRecord[]>([]);
  const [environments, setEnvironments] = useState<CloudEnvironmentRecord[]>([]);
  const [findings, setFindings] = useState<SecurityFindingRecord[]>([]);
  const [loading, setLoading] = useState(true);

  const loadAll = async () => {
    setLoading(true);
    const [ov, ags, envs, fds] = await Promise.all([
      fetchCSPMOverview().catch(() => null),
      fetchCSPMAgents().catch(() => []),
      fetchCloudEnvironments().catch(() => []),
      fetchSecurityFindings({ limit: 20 }).then(r => r.findings).catch(() => []),
    ]);
    setOverview(ov); setAgents(ags); setEnvironments(envs); setFindings(fds);
    setLoading(false);
  };

  useEffect(() => { loadAll(); }, []);

  const NAV: { id: SubView; label: string; icon: any; count?: number }[] = [
    { id: "overview", label: "Overview", icon: Layers },
    { id: "agents", label: "AI Agents", icon: Cpu, count: agents.length },
    { id: "findings", label: "Findings", icon: AlertTriangle, count: overview?.total_open_findings },
    { id: "scans", label: "Scan History", icon: Activity },
    { id: "environments", label: "Cloud Environments", icon: Globe, count: environments.length },
    { id: "rules", label: "Security Rules", icon: BookOpen },
  ];

  return (
    <div className="space-y-4">
      {/* Section Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-2">
          <Shield className="w-5 h-5 text-cyan-400" />
          LUME AI-CSPM Platform
        </h2>
        <button onClick={loadAll} disabled={loading} className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 transition">
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />Refresh
        </button>
      </div>

      {/* Sub-Navigation */}
      <div className="flex gap-1 overflow-x-auto no-scrollbar border-b border-slate-800/60 pb-px">
        {NAV.map(n => {
          const Icon = n.icon;
          const active = subView === n.id;
          return (
            <button key={n.id} onClick={() => setSubView(n.id)}
              className={`flex items-center gap-1.5 py-2 px-3 text-xs font-semibold border-b-2 transition whitespace-nowrap ${active ? "border-cyan-400 text-cyan-400" : "border-transparent text-slate-400 hover:text-slate-200"}`}>
              <Icon className="w-3.5 h-3.5" />{n.label}
              {n.count !== undefined && n.count > 0 && <span className="text-[9px] font-mono px-1.5 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">{n.count}</span>}
            </button>
          );
        })}
      </div>

      {/* Sub-View Content */}
      {subView === "overview" && <OverviewSection overview={overview} agents={agents} findings={findings} onNavigate={setSubView} />}
      {subView === "agents" && <AgentsSection agents={agents} onNavigate={setSubView} />}
      {subView === "findings" && <FindingsSection onRefresh={() => { loadAll(); onRefresh(); }} />}
      {subView === "scans" && <ScansSection />}
      {subView === "environments" && <EnvironmentsSection environments={environments} />}
      {subView === "rules" && <RulesSection />}
    </div>
  );
};
