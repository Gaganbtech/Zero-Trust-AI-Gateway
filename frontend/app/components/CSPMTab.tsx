import React, { useState } from "react";
import {
  Cloud,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  ShieldCheck,
  Terminal,
  ExternalLink
} from "lucide-react";
import { CSPMScanSummary, PostureCheckResult, triggerCSPMScan } from "../lib/api";

interface CSPMTabProps {
  cspmSummary: CSPMScanSummary | null;
  onRefresh: () => void;
}

export const CSPMTab: React.FC<CSPMTabProps> = ({ cspmSummary, onRefresh }) => {
  const [loading, setLoading] = useState<boolean>(false);
  const [filterStatus, setFilterStatus] = useState<string>("ALL");
  const [searchFilter, setSearchFilter] = useState<string>("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleScan = async (env: string) => {
    setLoading(true);
    try {
      await triggerCSPMScan(env);
      onRefresh();
    } catch (err) {
      console.error("Scan trigger failed:", err);
    } finally {
      setLoading(false);
    }
  };

  const copyCommand = (e: React.MouseEvent, id: string, cmd: string) => {
    e.stopPropagation();
    navigator.clipboard.writeText(cmd);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const findings = cspmSummary?.findings || [];
  const filtered = findings.filter((f) => {
    const matchStatus = filterStatus === "ALL" || f.status === filterStatus || f.severity === filterStatus;
    const matchSearch =
      !searchFilter.trim() ||
      f.name.toLowerCase().includes(searchFilter.toLowerCase()) ||
      f.check_id.toLowerCase().includes(searchFilter.toLowerCase()) ||
      f.description.toLowerCase().includes(searchFilter.toLowerCase());
    return matchStatus && matchSearch;
  });

  return (
    <div className="space-y-6">
      {/* Header and Scan Triggers */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900 to-indigo-950/60 border border-slate-800 shadow-xl">
        <div className="space-y-1">
          <div className="flex items-center space-x-2">
            <span className="p-1.5 rounded-lg bg-cyan-950 border border-cyan-800/60 text-cyan-400">
              <Cloud className="w-4 h-4" />
            </span>
            <h3 className="text-lg font-bold text-white tracking-tight">AI Cloud Security Posture Management (AI-CSPM)</h3>
          </div>
          <p className="text-xs text-slate-400">
            Continuous posture evaluation across AI model endpoints, IAM least-privilege, S3 buckets, vector DBs, and Kubernetes pods.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            disabled={loading}
            onClick={() => handleScan("AWS / EKS Production")}
            className="flex items-center space-x-1.5 px-3.5 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-medium rounded-xl shadow-lg shadow-cyan-950/40 transition disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            <span>{loading ? "Scanning Cloud..." : "Trigger Full Scan"}</span>
          </button>
        </div>
      </div>

      {/* Summary Score Cards */}
      {cspmSummary && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3.5">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow">
            <span className="text-xs text-slate-400">Compliance Score</span>
            <p className="text-2xl font-bold font-mono text-cyan-400 mt-1">{cspmSummary.compliance_score}%</p>
            <span className="text-[10px] text-slate-500 font-mono">Passing Threshold: 80%</span>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow">
            <span className="text-xs text-slate-400">Passed Checks</span>
            <p className="text-2xl font-bold font-mono text-emerald-400 mt-1">{cspmSummary.passed_checks}</p>
            <span className="text-[10px] text-emerald-500 font-mono">Zero Remediation Needed</span>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow">
            <span className="text-xs text-slate-400">Failed Checks</span>
            <p className="text-2xl font-bold font-mono text-red-400 mt-1">{cspmSummary.failed_checks}</p>
            <span className="text-[10px] text-red-500 font-mono">Requires Action</span>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow">
            <span className="text-xs text-slate-400">Critical Findings</span>
            <p className="text-2xl font-bold font-mono text-rose-400 mt-1">{cspmSummary.critical_findings}</p>
            <span className="text-[10px] text-rose-500 font-mono">IMDS / Root IAM</span>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow">
            <span className="text-xs text-slate-400">High Findings</span>
            <p className="text-2xl font-bold font-mono text-amber-400 mt-1">{cspmSummary.high_findings}</p>
            <span className="text-[10px] text-amber-500 font-mono">Encryption &amp; KMS</span>
          </div>
        </div>
      )}

      {/* Filter and Findings List */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center space-x-2 flex-1 max-w-sm">
            <input
              type="text"
              placeholder="Search checks by ID or name..."
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-center space-x-2 flex-wrap">
            {["ALL", "FAIL", "PASS", "CRITICAL", "HIGH"].map((st) => (
              <button
                key={st}
                onClick={() => setFilterStatus(st)}
                className={`px-3 py-1 rounded-md text-xs font-mono transition ${
                  filterStatus === st
                    ? "bg-slate-800 text-cyan-400 font-bold border border-slate-700"
                    : "bg-slate-950 text-slate-400 hover:text-white border border-slate-800"
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>

        {/* Findings Accordion */}
        <div className="space-y-3">
          {filtered.map((chk) => {
            const isExpanded = expandedId === chk.check_id;

            return (
              <div
                key={chk.check_id}
                onClick={() => setExpandedId(isExpanded ? null : chk.check_id)}
                className="p-5 rounded-2xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition cursor-pointer space-y-3 shadow-xl"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                          chk.status === "PASS"
                            ? "bg-emerald-950 text-emerald-400 border border-emerald-800/60"
                            : chk.status === "FAIL"
                            ? "bg-red-950 text-red-400 border border-red-800/60"
                            : "bg-amber-950 text-amber-400 border border-amber-800/60"
                        }`}
                      >
                        {chk.status}
                      </span>
                      <span className="text-[10px] font-mono text-slate-400">{chk.check_id}</span>
                      <span className="text-[10px] font-mono text-cyan-400">({chk.category})</span>
                    </div>
                    <h4 className="text-sm font-bold text-white tracking-tight">{chk.name}</h4>
                    <p className="text-xs text-slate-400">{chk.description}</p>
                  </div>

                  <div className="flex items-center space-x-3 shrink-0">
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                        chk.severity === "CRITICAL"
                          ? "bg-rose-950 text-rose-400 border border-rose-800/60"
                          : chk.severity === "HIGH"
                          ? "bg-amber-950 text-amber-400 border border-amber-800/60"
                          : "bg-slate-800 text-slate-300"
                      }`}
                    >
                      {chk.severity}
                    </span>
                    {isExpanded ? <ChevronDown className="w-4 h-4 text-slate-400" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="pt-4 border-t border-slate-800 space-y-4" onClick={(e) => e.stopPropagation()}>
                    <div className="space-y-1">
                      <span className="text-xs font-semibold text-slate-300">Remediation Guidance:</span>
                      <p className="text-xs text-slate-400 leading-relaxed">{chk.remediation_guidance}</p>
                    </div>

                    {/* Copyable CLI Command */}
                    {chk.remediation_command && (
                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between text-xs text-slate-400">
                          <span className="flex items-center space-x-1.5">
                            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                            <span className="font-semibold text-slate-300">CLI Remediation Command:</span>
                          </span>
                          <button
                            onClick={(e) => copyCommand(e, chk.check_id, chk.remediation_command)}
                            className="flex items-center space-x-1 text-cyan-400 hover:text-cyan-300"
                          >
                            {copiedId === chk.check_id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                            <span>{copiedId === chk.check_id ? "Copied" : "Copy Command"}</span>
                          </button>
                        </div>
                        <pre className="bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-cyan-300 overflow-x-auto whitespace-pre-wrap">
                          {chk.remediation_command}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
