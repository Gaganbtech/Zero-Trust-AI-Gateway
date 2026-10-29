import React, { useState } from "react";
import { X, ShieldAlert, Send, Clock, UserCheck } from "lucide-react";
import { IncidentRecord, addIncidentNote, updateIncidentStatus } from "../lib/api";

interface IncidentDetailModalProps {
  incident: IncidentRecord | null;
  onClose: () => void;
  onRefresh: () => void;
}

export const IncidentDetailModal: React.FC<IncidentDetailModalProps> = ({
  incident,
  onClose,
  onRefresh
}) => {
  const [noteInput, setNoteInput] = useState<string>("");
  const [submittingNote, setSubmittingNote] = useState<boolean>(false);

  if (!incident) return null;

  const handleAddNote = async () => {
    if (!noteInput.trim()) return;
    setSubmittingNote(true);
    try {
      await addIncidentNote(incident.id, noteInput);
      setNoteInput("");
      onRefresh();
      onClose();
    } catch (err) {
      console.error("Failed to add note:", err);
    } finally {
      setSubmittingNote(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 space-y-5 shadow-2xl overflow-y-auto max-h-[90vh]">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center space-x-2.5">
            <ShieldAlert className="w-5 h-5 text-red-400" />
            <h3 className="text-base font-bold text-white">{incident.title}</h3>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="space-y-3 text-xs">
          <div>
            <span className="text-slate-400">Incident Description:</span>
            <p className="text-slate-200 mt-1 leading-relaxed bg-slate-950 p-3 rounded-xl border border-slate-800">
              {incident.description}
            </p>
          </div>

          <div>
            <span className="text-slate-400">Recommended Remediation Guidance:</span>
            <p className="text-cyan-300 mt-1 leading-relaxed bg-slate-950 p-3 rounded-xl border border-slate-800 font-mono">
              {incident.remediation_guidance}
            </p>
          </div>

          {incident.analyst_notes && (
            <div>
              <span className="text-slate-400">Analyst Investigation Notes:</span>
              <p className="text-slate-300 mt-1 bg-slate-950 p-3 rounded-xl border border-slate-800 font-mono whitespace-pre-wrap">
                {incident.analyst_notes}
              </p>
            </div>
          )}

          {/* Add Analyst Note Form */}
          <div className="space-y-2 pt-2 border-t border-slate-800">
            <label className="text-xs font-semibold text-slate-300">Add Analyst Note / Triage Comment:</label>
            <div className="flex items-center space-x-2">
              <input
                type="text"
                placeholder="Enter notes on investigation findings, root cause, or actions taken..."
                value={noteInput}
                onChange={(e) => setNoteInput(e.target.value)}
                className="flex-1 bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
              <button
                disabled={submittingNote || !noteInput.trim()}
                onClick={handleAddNote}
                className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-medium rounded-xl transition disabled:opacity-50 flex items-center space-x-1.5"
              >
                <Send className="w-3.5 h-3.5" />
                <span>Save</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
