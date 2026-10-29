import React, { useState } from "react";
import {
  Terminal,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  Clock,
  Layers,
  ChevronRight
} from "lucide-react";
import { SecurityEvent } from "../lib/api";

interface EventsTabProps {
  events: SecurityEvent[];
  onSelectEvent: (event: SecurityEvent) => void;
}

export const EventsTab: React.FC<EventsTabProps> = ({ events, onSelectEvent }) => {
  const [filterDecision, setFilterDecision] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");

  const filteredEvents = events.filter((e) => {
    const matchDec = filterDecision === "ALL" || e.decision === filterDecision;
    const matchSearch =
      !searchQuery.trim() ||
      e.agent_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.tool.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.destination.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.reason.toLowerCase().includes(searchQuery.toLowerCase()) ||
      e.event_id.toLowerCase().includes(searchQuery.toLowerCase());
    return matchDec && matchSearch;
  });

  return (
    <div className="space-y-6">
      {/* Search and Filters Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl bg-slate-900 border border-slate-800">
        <div className="flex items-center space-x-3 flex-1 max-w-md">
          <div className="relative w-full">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search by Agent, Tool, Destination, Reason, Event ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <span className="text-xs text-slate-400">Decision:</span>
          <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-0.5 text-xs">
            {["ALL", "ALLOW", "BLOCK"].map((dec) => (
              <button
                key={dec}
                onClick={() => setFilterDecision(dec)}
                className={`px-3 py-1 rounded-md font-mono transition ${
                  filterDecision === dec
                    ? "bg-slate-800 text-cyan-400 font-bold"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                {dec}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Events Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase font-mono text-[11px]">
              <tr>
                <th className="py-3 px-4">Decision</th>
                <th className="py-3 px-4">Event ID</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Agent ID</th>
                <th className="py-3 px-4">Tool</th>
                <th className="py-3 px-4">Operation</th>
                <th className="py-3 px-4">Destination</th>
                <th className="py-3 px-4">Reason</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredEvents.length > 0 ? (
                filteredEvents.map((evt) => (
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
                    <td className="py-2.5 px-4 text-slate-400 text-[11px] font-mono">
                      {evt.event_id.slice(0, 14)}...
                    </td>
                    <td className="py-2.5 px-4 text-slate-400 text-[11px]">
                      {new Date(evt.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-4 text-cyan-300 font-semibold">{evt.agent_id}</td>
                    <td className="py-2.5 px-4 text-white">{evt.tool}</td>
                    <td className="py-2.5 px-4 text-slate-400">{evt.operation}</td>
                    <td className="py-2.5 px-4 text-slate-400 max-w-xs truncate">{evt.destination}</td>
                    <td className="py-2.5 px-4 text-slate-300">{evt.reason}</td>
                    <td className="py-2.5 px-4 text-right">
                      <ChevronRight className="w-4 h-4 text-slate-500 inline" />
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-500">
                    No security events found matching the filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
