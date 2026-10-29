import React, { useState } from "react";
import { FileText, ShieldCheck, ShieldAlert, RefreshCw, Layers, CheckCircle2, XCircle } from "lucide-react";
import { HashChainVerification, SecurityEvent, verifyAuditChain } from "../lib/api";

interface TamperTabProps {
  auditReport: HashChainVerification | null;
  events: SecurityEvent[];
  onRefresh: () => void;
}

export const TamperTab: React.FC<TamperTabProps> = ({ auditReport, events, onRefresh }) => {
  const [verifying, setVerifying] = useState<boolean>(false);
  const [currentReport, setCurrentReport] = useState<HashChainVerification | null>(auditReport);

  const handleVerify = async () => {
    setVerifying(true);
    try {
      const res = await verifyAuditChain();
      setCurrentReport(res);
      onRefresh();
    } catch (err: any) {
      setCurrentReport({ valid: false, error: err.message });
    } finally {
      setVerifying(false);
    }
  };

  const report = currentReport || auditReport;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
          <FileText className="w-4 h-4 text-cyan-400" />
          <span>Tamper-Evident HMAC-SHA256 Cryptographic Audit Ledger</span>
        </h3>

        <button
          disabled={verifying}
          onClick={handleVerify}
          className="flex items-center space-x-2 px-3.5 py-1.5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-medium rounded-xl shadow-lg shadow-purple-950/40 transition disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${verifying ? "animate-spin" : ""}`} />
          <span>{verifying ? "Verifying Ledger..." : "Verify Chain Integrity"}</span>
        </button>
      </div>

      {/* Verification Card */}
      {report && (
        <div
          className={`p-6 rounded-2xl border ${
            report.valid
              ? "bg-emerald-950/30 border-emerald-800/60"
              : "bg-red-950/30 border-red-800/60"
          } space-y-4 shadow-xl`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              {report.valid ? (
                <CheckCircle2 className="w-8 h-8 text-emerald-400" />
              ) : (
                <XCircle className="w-8 h-8 text-red-400" />
              )}
              <div>
                <h4 className="text-base font-bold text-white">
                  {report.valid
                    ? "Cryptographic Integrity Verified (Zero Tampering Detected)"
                    : "Integrity Violation Detected in Audit Log!"}
                </h4>
                <p className="text-xs text-slate-300">
                  {report.valid
                    ? `All ${report.total_events_verified ?? events.length} audit blocks mathematically chained via HMAC-SHA256.`
                    : report.error || "A block has been modified, injected, or deleted without authorization."}
                </p>
              </div>
            </div>

            {report.head_hash && (
              <div className="text-right">
                <span className="text-[10px] text-slate-400 font-mono uppercase">Current Head Hash</span>
                <div className="text-xs font-mono text-cyan-400">{report.head_hash.slice(0, 20)}...</div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Audit Blocks Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase text-[11px]">
              <tr>
                <th className="py-3 px-4">Block / ID</th>
                <th className="py-3 px-4">Event ID</th>
                <th className="py-3 px-4">Agent ID</th>
                <th className="py-3 px-4">Decision</th>
                <th className="py-3 px-4">HMAC-SHA256 Hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {events.map((evt, idx) => (
                <tr key={evt.event_id} className="hover:bg-slate-800/40 transition">
                  <td className="py-2.5 px-4 text-cyan-400 font-bold">#{evt.id || idx + 1}</td>
                  <td className="py-2.5 px-4 text-slate-300">{evt.event_id.slice(0, 16)}...</td>
                  <td className="py-2.5 px-4 text-slate-400">{evt.agent_id}</td>
                  <td className="py-2.5 px-4">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        evt.decision === "ALLOW"
                          ? "bg-emerald-950 text-emerald-400"
                          : "bg-red-950 text-red-400"
                      }`}
                    >
                      {evt.decision}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-slate-500 text-[11px] font-mono truncate max-w-sm">
                    {evt.tamper_chain_hash || "--"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
