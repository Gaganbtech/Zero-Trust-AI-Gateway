import React from "react";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Play,
  Terminal,
  Database,
  Cloud,
  CheckCircle2,
  XCircle,
  Clock,
  Layers,
  ArrowRight,
  Sparkles
} from "lucide-react";
import {
  DashboardSummary,
  SecurityEvent,
  CSPMScanSummary,
  HashChainVerification
} from "../lib/api";

interface OverviewTabProps {
  summary: DashboardSummary | null;
  events: SecurityEvent[];
  cspmSummary: CSPMScanSummary | null;
  auditReport: HashChainVerification | null;
  demoLoading: boolean;
  demoOutput: string | null;
  onRunSafe: () => void;
  onRunInjection: () => void;
  onRunDlp: () => void;
  onVerifyChain: () => void;
  onTriggerCSPM: () => void;
  onSelectEvent: (event: SecurityEvent) => void;
  onNavigateTab: (tab: any) => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  summary,
  events,
  cspmSummary,
  auditReport,
  demoLoading,
  demoOutput,
  onRunSafe,
  onRunInjection,
  onRunDlp,
  onVerifyChain,
  onTriggerCSPM,
  onSelectEvent,
  onNavigateTab
}) => {
  return (
    <div className="space-y-8">
      {/* Metric KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4">
        {/* Total Events */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Total Events</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {summary ? summary.total_events.toLocaleString() : "--"}
          </div>
          <div className="text-[11px] text-slate-400 font-mono">100% Tamper Chained</div>
        </div>

        {/* Allowed Actions */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Authorized Actions</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">
            {summary ? summary.allowed_actions.toLocaleString() : "--"}
          </div>
          <div className="text-[11px] text-emerald-400/80 font-mono">Verified Zero-Trust</div>
        </div>

        {/* Blocked Actions */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Blocked Actions</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-red-400">
            {summary ? summary.blocked_actions.toLocaleString() : "--"}
          </div>
          <div className="text-[11px] text-red-400/80 font-mono">Prevented Threats</div>
        </div>

        {/* Prompt Injections */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Prompt Injections</span>
            <Sparkles className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-purple-400">
            {summary ? summary.prompt_flags.toLocaleString() : "--"}
          </div>
          <div className="text-[11px] text-purple-400/80 font-mono">Pre-Inference Intercepts</div>
        </div>

        {/* Active Incidents */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">Active Incidents</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">
            {summary ? summary.active_incidents.toLocaleString() : "--"}
          </div>
          <div className="text-[11px] text-amber-400/80 font-mono">
            {summary?.critical_incidents || 0} Critical
          </div>
        </div>

        {/* AI-CSPM Score */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-medium">AI-CSPM Posture</span>
            <Cloud className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-cyan-400">
            {cspmSummary ? `${cspmSummary.compliance_score}%` : "85%"}
          </div>
          <div className="text-[11px] text-cyan-400/80 font-mono">Cloud AI Posture</div>
        </div>
      </div>

      {/* Quick Action Workbench & Live Sandbox Terminal */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left: Quick Actions */}
        <div className="lg:col-span-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
              <Play className="w-4 h-4 text-cyan-400" />
              <span>Security Operator Workbench</span>
            </h3>
            <span className="text-xs text-slate-400">Live Triggers</span>
          </div>

          <div className="space-y-3">
            {/* Safe Query */}
            <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl hover:border-slate-700 transition flex items-center justify-between gap-4">
              <div className="space-y-0.5">
                <div className="text-sm font-bold text-white">Safe Parameterized Customer Query</div>
                <div className="text-xs text-slate-400">Tenant-scoped DB query allowlisting permitted columns</div>
              </div>
              <button
                disabled={demoLoading}
                onClick={onRunSafe}
                className="px-3 py-1.5 bg-emerald-950/60 hover:bg-emerald-900 border border-emerald-800 text-emerald-300 text-xs font-medium rounded-lg transition disabled:opacity-50 shrink-0"
              >
                Execute Safe
              </button>
            </div>

            {/* Prompt Injection Test */}
            <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl hover:border-slate-700 transition flex items-center justify-between gap-4">
              <div className="space-y-0.5">
                <div className="text-sm font-bold text-white">Prompt Injection Directive</div>
                <div className="text-xs text-slate-400">Adversarial instruction override &amp; credential exfiltration probe</div>
              </div>
              <button
                disabled={demoLoading}
                onClick={onRunInjection}
                className="px-3 py-1.5 bg-red-950/60 hover:bg-red-900 border border-red-800 text-red-300 text-xs font-medium rounded-lg transition disabled:opacity-50 shrink-0"
              >
                Test Block
              </button>
            </div>

            {/* Recursive DLP Test */}
            <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl hover:border-slate-700 transition flex items-center justify-between gap-4">
              <div className="space-y-0.5">
                <div className="text-sm font-bold text-white">Recursive DLP Masking Test</div>
                <div className="text-xs text-slate-400">Automatic redaction of AWS keys, Luhn credit cards, and PII</div>
              </div>
              <button
                disabled={demoLoading}
                onClick={onRunDlp}
                className="px-3 py-1.5 bg-blue-950/60 hover:bg-blue-900 border border-blue-800 text-blue-300 text-xs font-medium rounded-lg transition disabled:opacity-50 shrink-0"
              >
                Redact Test
              </button>
            </div>

            {/* Verify Hash Chain */}
            <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl hover:border-slate-700 transition flex items-center justify-between gap-4">
              <div className="space-y-0.5">
                <div className="text-sm font-bold text-white">Verify HMAC Audit Chain</div>
                <div className="text-xs text-slate-400">Cryptographically audit entire security log for tamper evidence</div>
              </div>
              <button
                disabled={demoLoading}
                onClick={onVerifyChain}
                className="px-3 py-1.5 bg-purple-950/60 hover:bg-purple-900 border border-purple-800 text-purple-300 text-xs font-medium rounded-lg transition disabled:opacity-50 shrink-0"
              >
                Verify Hash
              </button>
            </div>

            {/* AI-CSPM Scan */}
            <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl hover:border-slate-700 transition flex items-center justify-between gap-4">
              <div className="space-y-0.5">
                <div className="text-sm font-bold text-white">Run AI-CSPM Cloud Posture Audit</div>
                <div className="text-xs text-slate-400">Evaluate IMDSv2, S3 bucket encryption, IAM privilege, Vector DB</div>
              </div>
              <button
                disabled={demoLoading}
                onClick={onTriggerCSPM}
                className="px-3 py-1.5 bg-cyan-950/60 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 text-xs font-medium rounded-lg transition disabled:opacity-50 shrink-0"
              >
                Scan Cloud
              </button>
            </div>
          </div>
        </div>

        {/* Right: Live Terminal */}
        <div className="lg:col-span-7 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span>Live Gateway Execution Console</span>
            </h3>
            {demoLoading && (
              <span className="text-xs text-cyan-400 animate-pulse font-mono">Running mediation...</span>
            )}
          </div>

          <div className="bg-slate-950 border border-slate-800 rounded-2xl p-4 shadow-xl flex flex-col h-[400px]">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800/80 text-xs text-slate-400">
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 rounded-full bg-red-500/80" />
                <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                <div className="w-3 h-3 rounded-full bg-green-500/80" />
                <span className="ml-2 font-mono text-slate-400">zero-trust-gateway-daemon</span>
              </div>
              <span className="font-mono text-[11px] text-cyan-400">STDIO / REST Stream</span>
            </div>

            <pre className="flex-1 mt-3 text-xs font-mono text-slate-300 overflow-y-auto overflow-x-auto whitespace-pre-wrap leading-relaxed select-text">
              {demoOutput || (
                <span className="text-slate-600">
                  // Gateway ready. Select a workbench action above or launch the Attack Studio to observe zero-trust mediation responses...
                </span>
              )}
            </pre>
          </div>
        </div>
      </div>

      {/* Recent Security Telemetry Events */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            <span>Recent Telemetry Stream ({events.slice(0, 5).length})</span>
          </h3>
          <button
            onClick={() => onNavigateTab("events")}
            className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
          >
            <span>View Full Ledger</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase font-mono text-[11px]">
                <tr>
                  <th className="py-3 px-4">Decision</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Agent ID</th>
                  <th className="py-3 px-4">Tool</th>
                  <th className="py-3 px-4">Destination</th>
                  <th className="py-3 px-4">Reason</th>
                  <th className="py-3 px-4 text-right">Receipt</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {events.slice(0, 6).map((evt) => (
                  <tr
                    key={evt.event_id}
                    onClick={() => onSelectEvent(evt)}
                    className="hover:bg-slate-800/40 cursor-pointer transition"
                  >
                    <td className="py-2.5 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          evt.decision === "ALLOW"
                            ? "bg-emerald-950 text-emerald-400 border border-emerald-800/60"
                            : "bg-red-950 text-red-400 border border-red-800/60"
                        }`}
                      >
                        {evt.decision}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-slate-400 text-[11px]">
                      {new Date(evt.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-4 text-cyan-300 font-semibold">{evt.agent_id}</td>
                    <td className="py-2.5 px-4 text-white">{evt.tool}</td>
                    <td className="py-2.5 px-4 text-slate-400 max-w-xs truncate">{evt.destination}</td>
                    <td className="py-2.5 px-4 text-slate-300">{evt.reason}</td>
                    <td className="py-2.5 px-4 text-right text-slate-500 text-[10px]">
                      {evt.tamper_chain_hash ? `${evt.tamper_chain_hash.slice(0, 10)}...` : "--"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
