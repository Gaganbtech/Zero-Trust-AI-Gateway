import React from "react";
import { X, Shield, Clock, FileText, CheckCircle2, AlertTriangle } from "lucide-react";
import { SecurityEvent } from "../lib/api";

interface EventDetailModalProps {
  event: SecurityEvent | null;
  onClose: () => void;
}

export const EventDetailModal: React.FC<EventDetailModalProps> = ({ event, onClose }) => {
  if (!event) return null;

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 space-y-5 shadow-2xl overflow-y-auto max-h-[90vh]">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center space-x-2.5">
            <Shield className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-bold text-white">Security Event #{event.id}</h3>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Details Grid */}
        <div className="grid grid-cols-2 gap-3 text-xs font-mono">
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-400">Event ID</span>
            <div className="text-white truncate">{event.event_id}</div>
          </div>
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-400">Decision</span>
            <div className={`font-bold ${event.decision === "ALLOW" ? "text-emerald-400" : "text-red-400"}`}>
              {event.decision}
            </div>
          </div>
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-400">Agent ID</span>
            <div className="text-cyan-300">{event.agent_id}</div>
          </div>
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-400">Tenant ID</span>
            <div className="text-white">{event.tenant_id}</div>
          </div>
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-400">Tool</span>
            <div className="text-white">{event.tool} ({event.operation})</div>
          </div>
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
            <span className="text-slate-400">Destination</span>
            <div className="text-slate-300 truncate">{event.destination}</div>
          </div>
        </div>

        {/* Reason & Risk */}
        <div className="space-y-1">
          <span className="text-xs font-semibold text-slate-400">Enforcement Reason:</span>
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-200 font-mono">
            {event.reason}
          </div>
        </div>

        {/* Raw Metadata JSON */}
        <div className="space-y-1">
          <span className="text-xs font-semibold text-slate-400">Security Context &amp; Metadata:</span>
          <pre className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs text-cyan-300 font-mono overflow-x-auto max-h-[220px]">
            {JSON.stringify(event.metadata || {}, null, 2)}
          </pre>
        </div>

        {/* Tamper Hash */}
        <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono space-y-1">
          <span className="text-slate-400">HMAC-SHA256 Hash Chain Receipt:</span>
          <div className="text-slate-300 break-all select-all">{event.tamper_chain_hash}</div>
        </div>
      </div>
    </div>
  );
};
