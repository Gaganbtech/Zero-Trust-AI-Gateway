import React, { useState, useEffect } from "react";
import {
  Layers,
  Database,
  Globe,
  Cloud,
  Terminal,
  Play,
  CheckCircle2,
  AlertTriangle,
  Code2,
  ShieldCheck,
  ShieldAlert,
  Copy,
  Check,
  RefreshCw
} from "lucide-react";
import {
  MCPToolSchema,
  fetchMCPTools,
  testMCPTool
} from "../lib/api";

interface MCPGatewayTabProps {
  activeTenant: string;
  onRefreshEvents: () => void;
}

export const MCPGatewayTab: React.FC<MCPGatewayTabProps> = ({ activeTenant, onRefreshEvents }) => {
  const [tools, setTools] = useState<MCPToolSchema[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedTool, setSelectedTool] = useState<string>("db_query");
  const [testArgsJson, setTestArgsJson] = useState<string>(
    JSON.stringify({ table: "customers", columns: ["id", "name", "email"], limit: 3 }, null, 2)
  );
  const [testResult, setTestResult] = useState<any>(null);
  const [testing, setTesting] = useState<boolean>(false);
  const [testError, setTestError] = useState<string | null>(null);
  const [copiedEndpoint, setCopiedEndpoint] = useState<boolean>(false);

  useEffect(() => {
    fetchMCPTools()
      .then((data) => {
        setTools(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Failed to load MCP tools:", err);
        setLoading(false);
      });
  }, []);

  const handleToolSelect = (toolName: string) => {
    setSelectedTool(toolName);
    setTestResult(null);
    setTestError(null);

    if (toolName === "db_query") {
      setTestArgsJson(JSON.stringify({ table: "customers", columns: ["id", "name", "email"], limit: 3 }, null, 2));
    } else if (toolName === "safe_http") {
      setTestArgsJson(JSON.stringify({ url: "https://httpbin.org/get" }, null, 2));
    } else if (toolName === "weather") {
      setTestArgsJson(JSON.stringify({ city: "Bengaluru" }, null, 2));
    } else if (toolName === "cspm_scan") {
      setTestArgsJson(JSON.stringify({ environment: "ALL" }, null, 2));
    }
  };

  const handleExecuteTool = async () => {
    setTesting(true);
    setTestResult(null);
    setTestError(null);

    try {
      let parsedArgs = {};
      try {
        parsedArgs = JSON.parse(testArgsJson);
      } catch (e: any) {
        throw new Error("Invalid JSON arguments format: " + e.message);
      }

      const res = await testMCPTool({
        tool_name: selectedTool,
        arguments: parsedArgs,
        agent_id: "demo-agent",
        tenant_id: activeTenant
      });

      setTestResult(res);
      onRefreshEvents();
    } catch (err: any) {
      setTestError(err.message || "MCP tool execution failed");
    } finally {
      setTesting(false);
    }
  };

  const copyEndpointUrl = () => {
    const url = typeof window !== "undefined" ? `${window.location.origin}/api/v1/mcp` : "http://127.0.0.1:8000/api/v1/mcp";
    navigator.clipboard.writeText(url);
    setCopiedEndpoint(true);
    setTimeout(() => setCopiedEndpoint(false), 2000);
  };

  return (
    <div className="space-y-8">
      {/* Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-slate-900 via-slate-900 to-cyan-950/40 border border-slate-800 p-6 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center space-x-2">
              <span className="p-1.5 rounded-lg bg-cyan-950/60 border border-cyan-800/60 text-cyan-400">
                <Layers className="w-4 h-4" />
              </span>
              <h2 className="text-xl font-bold text-white tracking-tight">Model Context Protocol (MCP) Gateway</h2>
            </div>
            <p className="text-sm text-slate-400 max-w-3xl">
              Connect autonomous AI agents, Claude Desktop, and LangChain orchestrators to internal tools securely. All MCP JSON-RPC 2.0 requests are authenticated, tenant-scoped, verified via OPA policies, and inspected by the DLP redaction engine.
            </p>
          </div>

          <div className="flex items-center space-x-3">
            <button
              onClick={copyEndpointUrl}
              className="flex items-center space-x-2 px-3.5 py-2 bg-slate-950 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 hover:text-white rounded-xl transition"
            >
              {copiedEndpoint ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4 text-cyan-400" />}
              <span className="font-mono">{copiedEndpoint ? "Copied!" : "POST /api/v1/mcp"}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Main Grid: Tool Directory & Interactive Client */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left: Registered MCP Tools */}
        <div className="lg:col-span-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
              <Code2 className="w-4 h-4 text-cyan-400" />
              <span>Registered Tools ({tools.length})</span>
            </h3>
            <span className="text-xs text-slate-400">Standard: 2024-11-05</span>
          </div>

          <div className="space-y-3.5">
            {tools.map((t) => {
              const isSelected = selectedTool === t.name;

              return (
                <div
                  key={t.name}
                  onClick={() => handleToolSelect(t.name)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer ${
                    isSelected
                      ? "bg-slate-900 border-cyan-500 shadow-md shadow-cyan-950/50"
                      : "bg-slate-900/60 border-slate-800 hover:border-slate-700 hover:bg-slate-900"
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <span className="text-sm font-bold text-white font-mono">{t.name}</span>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-mono font-medium">
                          MCP Tool
                        </span>
                      </div>
                      <p className="text-xs text-slate-400">{t.description}</p>
                    </div>
                  </div>

                  {/* Policy Tag Badges */}
                  <div className="mt-3 pt-3 border-t border-slate-800/80 grid grid-cols-2 gap-2 text-[11px]">
                    <div className="text-slate-400">
                      <span className="text-slate-500">Scope:</span>{" "}
                      <span className="font-mono text-cyan-400">{t.zero_trust_policy?.required_scope || "standard"}</span>
                    </div>
                    <div className="text-slate-400">
                      <span className="text-slate-500">Guard:</span>{" "}
                      <span className="font-mono text-emerald-400">{t.zero_trust_policy?.enforcement || "Zero-Trust"}</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Live MCP Client Sandbox */}
        <div className="lg:col-span-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span>Interactive MCP JSON-RPC Sandbox</span>
            </h3>
            <span className="text-xs font-mono text-cyan-400">{selectedTool}</span>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4 shadow-xl">
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-400">Tool Arguments (JSON):</label>
              <textarea
                value={testArgsJson}
                onChange={(e) => setTestArgsJson(e.target.value)}
                rows={5}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition"
              />
            </div>

            <div className="flex items-center justify-between">
              <span className="text-[11px] text-slate-400 font-mono">
                Workload Tenant: <span className="text-white font-semibold">{activeTenant}</span>
              </span>

              <button
                disabled={testing}
                onClick={handleExecuteTool}
                className="flex items-center space-x-2 px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-medium rounded-xl shadow-lg shadow-cyan-950/40 transition disabled:opacity-50"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>{testing ? "Executing..." : "Call MCP Tool"}</span>
              </button>
            </div>

            {testError && (
              <div className="p-3 rounded-xl bg-red-950/50 border border-red-800 text-red-300 text-xs flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                <span>{testError}</span>
              </div>
            )}

            {testResult && (
              <div className="space-y-3 pt-2 border-t border-slate-800">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-slate-300 flex items-center space-x-1.5">
                    {testResult.error ? (
                      <ShieldAlert className="w-4 h-4 text-red-400" />
                    ) : (
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    )}
                    <span>
                      {testResult.error ? "MCP Execution Blocked" : "MCP Response Received"}
                    </span>
                  </span>
                  <span className="text-slate-400 font-mono">JSON-RPC 2.0</span>
                </div>

                <pre className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 text-xs font-mono text-slate-200 overflow-x-auto max-h-[300px]">
                  {JSON.stringify(testResult, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
