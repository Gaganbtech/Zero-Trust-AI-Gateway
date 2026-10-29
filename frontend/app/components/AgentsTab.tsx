import React from "react";
import { Cpu, ShieldCheck, Key, CheckCircle2, Lock } from "lucide-react";
import { AgentRecord } from "../lib/api";

interface AgentsTabProps {
  agents: AgentRecord[];
}

export const AgentsTab: React.FC<AgentsTabProps> = ({ agents }) => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
          <Cpu className="w-4 h-4 text-cyan-400" />
          <span>Registered AI Agents &amp; Workloads ({agents.length})</span>
        </h3>
        <span className="text-xs text-slate-400">Cryptographically Enforced Identities</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {agents.map((agent) => (
          <div
            key={agent.id}
            className="p-5 rounded-2xl bg-slate-900 border border-slate-800 space-y-4 hover:border-slate-700 transition shadow-xl"
          >
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center space-x-2">
                  <h4 className="text-sm font-bold text-white font-mono">{agent.name || agent.id}</h4>
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                      agent.status === "ACTIVE"
                        ? "bg-emerald-950 text-emerald-400 border border-emerald-800/60"
                        : "bg-red-950 text-red-400 border border-red-800/60"
                    }`}
                  >
                    {agent.status}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1">{agent.description || "Autonomous AI agent workload"}</p>
              </div>

              <div className="p-2 rounded-xl bg-slate-950 border border-slate-800 text-cyan-400">
                <Cpu className="w-4 h-4" />
              </div>
            </div>

            <div className="space-y-2 pt-2 border-t border-slate-800 text-xs font-mono">
              <div className="flex items-center justify-between text-slate-400">
                <span>Tenant:</span>
                <span className="text-white font-semibold">{agent.tenant_id}</span>
              </div>
              <div className="flex items-center justify-between text-slate-400">
                <span>Agent ID:</span>
                <span className="text-cyan-300 truncate max-w-[180px]">{agent.id}</span>
              </div>
            </div>

            {/* Scopes */}
            <div className="space-y-1.5 pt-2 border-t border-slate-800">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                Assigned Scopes:
              </span>
              <div className="flex flex-wrap gap-1.5">
                {(agent.scopes || []).map((scope, idx) => (
                  <span
                    key={idx}
                    className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-cyan-400 border border-slate-800"
                  >
                    {scope}
                  </span>
                ))}
              </div>
            </div>

            {/* Allowed Tools */}
            <div className="space-y-1.5 pt-2 border-t border-slate-800">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                Allowed Tools:
              </span>
              <div className="flex flex-wrap gap-1.5">
                {(agent.allowed_tools || []).map((tool, idx) => (
                  <span
                    key={idx}
                    className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-emerald-400 border border-slate-800"
                  >
                    {tool}
                  </span>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
