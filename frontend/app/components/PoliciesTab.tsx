import React from "react";
import { Lock, FileText, CheckCircle2, ShieldCheck } from "lucide-react";
import { PolicyRecord } from "../lib/api";

interface PoliciesTabProps {
  policies: PolicyRecord[];
}

export const PoliciesTab: React.FC<PoliciesTabProps> = ({ policies }) => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
          <Lock className="w-4 h-4 text-cyan-400" />
          <span>Active Open Policy Agent (OPA) Rego Policies ({policies.length})</span>
        </h3>
        <span className="text-xs text-slate-400">Rego v1 Policy Specification</span>
      </div>

      <div className="space-y-4">
        {policies.map((pol) => (
          <div
            key={pol.id}
            className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4 shadow-xl"
          >
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center space-x-2">
                  <h4 className="text-sm font-bold text-white font-mono">{pol.name}</h4>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/60 font-bold uppercase">
                    {pol.is_active ? "ACTIVE & ENFORCED" : "INACTIVE"}
                  </span>
                  <span className="text-xs font-mono text-cyan-400">v{pol.version}</span>
                </div>
                <p className="text-xs text-slate-400 font-mono mt-1">SHA256 Checksum: {pol.checksum}</p>
              </div>

              <div className="p-2 rounded-xl bg-slate-950 border border-slate-800 text-cyan-400">
                <FileText className="w-4 h-4" />
              </div>
            </div>

            {/* Rego Code Viewer */}
            <div className="space-y-1.5">
              <span className="text-xs font-semibold text-slate-400">Policy Source Code (Rego):</span>
              <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs font-mono text-cyan-300 overflow-x-auto max-h-[400px] leading-relaxed">
                {pol.rego_code}
              </pre>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
