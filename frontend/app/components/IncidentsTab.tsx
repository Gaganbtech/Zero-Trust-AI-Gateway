import React, { useState } from "react";
import {
  ShieldAlert,
  AlertTriangle,
  Clock,
  CheckCircle2,
  ChevronRight,
  Send,
  UserCheck
} from "lucide-react";
import { IncidentRecord, updateIncidentStatus, addIncidentNote } from "../lib/api";

interface IncidentsTabProps {
  incidents: IncidentRecord[];
  onSelectIncident: (incident: IncidentRecord) => void;
  onRefresh: () => void;
}

export const IncidentsTab: React.FC<IncidentsTabProps> = ({
  incidents,
  onSelectIncident,
  onRefresh
}) => {
  const [updatingId, setUpdatingId] = useState<string | null>(null);

  const handleStatusChange = async (e: React.MouseEvent, id: string, newStatus: string) => {
    e.stopPropagation();
    setUpdatingId(id);
    try {
      await updateIncidentStatus(id, newStatus);
      onRefresh();
    } catch (err) {
      console.error("Status update failed:", err);
    } finally {
      setUpdatingId(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
          <ShieldAlert className="w-4 h-4 text-red-400" />
          <span>Security Incidents Queue ({incidents.length})</span>
        </h3>
        <span className="text-xs text-slate-400">Rule-based threat correlation</span>
      </div>

      <div className="space-y-3.5">
        {incidents.length > 0 ? (
          incidents.map((inc) => (
            <div
              key={inc.id}
              onClick={() => onSelectIncident(inc)}
              className="p-5 rounded-2xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition cursor-pointer space-y-3 shadow-xl"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                        inc.severity === "CRITICAL"
                          ? "bg-red-950 text-red-400 border border-red-800/60"
                          : inc.severity === "HIGH"
                          ? "bg-amber-950 text-amber-400 border border-amber-800/60"
                          : "bg-blue-950 text-blue-400 border border-blue-800/60"
                      }`}
                    >
                      {inc.severity}
                    </span>
                    <span className="text-xs font-mono font-bold text-white">{inc.id}</span>
                    <span className="text-xs font-mono text-slate-400">({inc.rule_name})</span>
                  </div>
                  <h4 className="text-sm font-bold text-white tracking-tight">{inc.title}</h4>
                  <p className="text-xs text-slate-400 line-clamp-2">{inc.description}</p>
                </div>

                <div className="flex items-center space-x-2 shrink-0">
                  <span
                    className={`text-[11px] font-mono px-2.5 py-1 rounded-lg font-bold border ${
                      inc.status === "OPEN"
                        ? "bg-red-950/60 text-red-300 border-red-800/60"
                        : inc.status === "INVESTIGATING"
                        ? "bg-amber-950/60 text-amber-300 border-amber-800/60"
                        : "bg-emerald-950/60 text-emerald-300 border-emerald-800/60"
                    }`}
                  >
                    {inc.status}
                  </span>
                </div>
              </div>

              {/* Status Update Quick Buttons */}
              <div
                className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="flex items-center space-x-2 text-slate-400 text-[11px] font-mono">
                  <span>Agent: <span className="text-cyan-400">{inc.agent_id}</span></span>
                  <span>•</span>
                  <span>Tenant: <span className="text-white">{inc.tenant_id}</span></span>
                  <span>•</span>
                  <span>Evidence: <span className="text-white">{inc.evidence_event_ids?.length || 0} event(s)</span></span>
                </div>

                <div className="flex items-center space-x-1.5">
                  <span className="text-[11px] text-slate-400 mr-1">Update Status:</span>
                  {["OPEN", "INVESTIGATING", "RESOLVED"].map((st) => (
                    <button
                      key={st}
                      disabled={updatingId === inc.id || inc.status === st}
                      onClick={(e) => handleStatusChange(e, inc.id, st)}
                      className={`text-[10px] font-mono px-2 py-0.5 rounded border transition disabled:opacity-40 ${
                        inc.status === st
                          ? "bg-slate-800 border-slate-700 text-slate-400 cursor-default"
                          : "bg-slate-950 hover:bg-slate-800 border-slate-800 text-slate-300 hover:text-white"
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ))
        ) : (
          <div className="p-12 text-center bg-slate-900 border border-slate-800 rounded-2xl text-slate-500">
            No active incidents detected. All agent tool actions are operating within zero-trust limits.
          </div>
        )}
      </div>
    </div>
  );
};
