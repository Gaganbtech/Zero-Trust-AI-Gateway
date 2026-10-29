import React from "react";
import { Shield, Radio, RefreshCw, Zap } from "lucide-react";

interface HeaderProps {
  sseConnected: boolean;
  refreshing: boolean;
  onRefresh: () => void;
  environment?: string;
  activeTenant: string;
  onTenantChange: (tenant: string) => void;
  onQuickSimulate: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  sseConnected,
  refreshing,
  onRefresh,
  environment = "development",
  activeTenant,
  onTenantChange,
  onQuickSimulate
}) => {
  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur sticky top-0 z-40 px-6 py-3.5">
      <div className="max-w-7xl mx-auto flex items-center justify-between flex-wrap gap-4">
        {/* Brand & Identity */}
        <div className="flex items-center space-x-3.5">
          <div className="relative">
            <div className="p-2.5 bg-gradient-to-br from-indigo-500/20 to-cyan-500/20 border border-cyan-500/40 rounded-xl shadow-lg shadow-cyan-950/50">
              <Shield className="w-6 h-6 text-cyan-400" />
            </div>
            <div className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-emerald-500 ring-2 ring-slate-950 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-bold text-white tracking-tight">Zero-Trust AI Gateway</h1>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/60 uppercase tracking-wider font-semibold">
                v2.0 Enterprise
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Runtime Mediation, LLM Guardrails &amp; Model Context Protocol (MCP) Security
            </p>
          </div>
        </div>

        {/* Global Controls & Status */}
        <div className="flex items-center space-x-3 flex-wrap">
          {/* Tenant Selector */}
          <div className="flex items-center space-x-2 bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1 text-xs">
            <span className="text-slate-400">Tenant:</span>
            <select
              value={activeTenant}
              onChange={(e) => onTenantChange(e.target.value)}
              className="bg-transparent text-cyan-400 font-mono font-medium focus:outline-none cursor-pointer"
            >
              <option value="tenant-alpha" className="bg-slate-900 text-white">tenant-alpha (Production)</option>
              <option value="tenant-beta" className="bg-slate-900 text-white">tenant-beta (Finance)</option>
              <option value="tenant-gamma" className="bg-slate-900 text-white">tenant-gamma (Analytics)</option>
            </select>
          </div>

          {/* SSE Live Feed Pill */}
          <div
            className={`flex items-center space-x-2 px-2.5 py-1 rounded-lg border text-xs font-mono transition-colors ${
              sseConnected
                ? "bg-emerald-950/40 border-emerald-800/60 text-emerald-300"
                : "bg-amber-950/40 border-amber-800/60 text-amber-300"
            }`}
          >
            <Radio className={`w-3.5 h-3.5 ${sseConnected ? "animate-pulse text-emerald-400" : "text-amber-400"}`} />
            <span>{sseConnected ? "SSE LIVE FEED" : "CONNECTING..."}</span>
          </div>

          {/* Quick Simulation Trigger */}
          <button
            onClick={onQuickSimulate}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white text-xs font-medium rounded-lg shadow-md shadow-red-950/40 transition-all hover:scale-105 active:scale-95"
            title="Launch Attack Simulation Studio"
          >
            <Zap className="w-3.5 h-3.5" />
            <span>Simulate Attack</span>
          </button>

          {/* Refresh Button */}
          <button
            onClick={onRefresh}
            disabled={refreshing}
            className="p-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 rounded-lg transition hover:text-white disabled:opacity-50"
            title="Refresh Dashboard Data"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? "animate-spin text-cyan-400" : ""}`} />
          </button>
        </div>
      </div>
    </header>
  );
};
