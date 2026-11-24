import {
  Activity,
  Box,
  Cpu,
  HardDrive,
  KeyRound,
  MemoryStick,
  RefreshCw,
  ShieldAlert,
} from "lucide-react";
import type { OverviewResponse } from "../api";

interface OverviewTabProps {
  data: OverviewResponse | null;
  loading: boolean;
  onRefresh: () => void;
  onNavigateTab: (tab: "overview" | "apps" | "approvals" | "keys") => void;
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${mins}m`;
  return `${mins}m`;
}

function MeterBar({ percent, color }: { percent: number; color: string }) {
  const clamped = Math.min(100, Math.max(0, percent));
  return (
    <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden mt-3">
      <div
        className={`h-full rounded-full transition-all ${color}`}
        style={{ width: `${clamped}%` }}
      />
    </div>
  );
}

export function OverviewTab({
  data,
  loading,
  onRefresh,
  onNavigateTab,
}: OverviewTabProps) {
  if (!data) {
    return (
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-8 text-center text-slate-400">
        {loading ? "Loading server health..." : "Could not load server overview."}
      </div>
    );
  }

  const runningApps = data.apps.filter((a) => a.status === "running");
  const cpuLoadPercent = Math.min(
    100,
    Math.round((data.metrics.loadAverage1m / Math.max(1, data.metrics.cpuCount)) * 100),
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold text-white">Server Overview</h2>
          <p className="text-sm text-slate-400">
            Host <span className="text-slate-200 font-medium">{data.metrics.hostname}</span>{" "}
            &middot; Up for {formatUptime(data.metrics.uptimeSeconds)}
          </p>
        </div>
        <button
          type="button"
          onClick={onRefresh}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3.5 py-2 text-sm font-medium text-slate-200 hover:bg-slate-800 transition cursor-pointer"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {data.pendingApprovals > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-amber-500/40 bg-amber-500/10 p-4">
          <div className="flex items-center gap-3">
            <ShieldAlert className="h-5 w-5 text-amber-400 shrink-0" />
            <div>
              <p className="text-sm font-semibold text-amber-200">
                {data.pendingApprovals} AI request
                {data.pendingApprovals === 1 ? "" : "s"} waiting for your approval
              </p>
              <p className="text-xs text-amber-300/80">
                Nothing changes until you click Approve.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => onNavigateTab("approvals")}
            className="rounded-lg bg-amber-400 px-3.5 py-1.5 text-xs font-semibold text-slate-950 hover:bg-amber-300 transition cursor-pointer"
          >
            Review Now
          </button>
        </div>
      )}

      {/* Live Resource Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex items-center justify-between text-slate-400 text-sm">
            <span>Processor (CPU)</span>
            <Cpu className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-semibold text-white">
              {cpuLoadPercent}%
            </span>
            <span className="text-xs text-slate-400">
              {data.metrics.cpuCount} core{data.metrics.cpuCount === 1 ? "" : "s"} (load{" "}
              {data.metrics.loadAverage1m})
            </span>
          </div>
          <MeterBar percent={cpuLoadPercent} color="bg-emerald-400" />
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex items-center justify-between text-slate-400 text-sm">
            <span>Memory (RAM)</span>
            <MemoryStick className="h-4 w-4 text-sky-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-semibold text-white">
              {data.metrics.memoryUsagePercent}%
            </span>
            <span className="text-xs text-slate-400">
              {Math.round(data.metrics.memoryUsedMb)} /{" "}
              {Math.round(data.metrics.memoryTotalMb)} MB
            </span>
          </div>
          <MeterBar percent={data.metrics.memoryUsagePercent} color="bg-sky-400" />
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex items-center justify-between text-slate-400 text-sm">
            <span>Storage (Disk)</span>
            <HardDrive className="h-4 w-4 text-violet-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-semibold text-white">
              {data.disk.usedPercent}%
            </span>
            <span className="text-xs text-slate-400">
              {data.disk.usedGb} / {data.disk.totalGb} GB used
            </span>
          </div>
          <MeterBar percent={data.disk.usedPercent} color="bg-violet-400" />
        </div>
      </div>

      {/* Quick Summary Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Box className="h-4 w-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-white">
                Running Apps ({runningApps.length} / {data.apps.length})
              </h3>
            </div>
            <button
              type="button"
              onClick={() => onNavigateTab("apps")}
              className="text-xs font-medium text-emerald-400 hover:text-emerald-300 cursor-pointer"
            >
              Manage Apps &rarr;
            </button>
          </div>
          {data.apps.length === 0 ? (
            <p className="text-sm text-slate-400">
              No apps launched yet. Launch one from the Apps tab or let your AI
              deploy one.
            </p>
          ) : (
            <ul className="space-y-2.5">
              {data.apps.slice(0, 6).map((app) => (
                <li
                  key={app.slug}
                  className="flex items-center justify-between rounded-xl border border-slate-800/80 bg-slate-950/60 px-3.5 py-2.5"
                >
                  <div>
                    <p className="text-sm font-medium text-white">{app.name}</p>
                    <p className="text-xs text-slate-400">
                      {app.domain ? `https://${app.domain}` : `Private (${app.slug})`}
                    </p>
                  </div>
                  <span
                    className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
                      app.status === "running"
                        ? "bg-emerald-500/15 text-emerald-300"
                        : app.status === "error"
                          ? "bg-rose-500/15 text-rose-300"
                          : "bg-slate-700/60 text-slate-300"
                    }`}
                  >
                    {app.status}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 flex flex-col justify-between gap-4">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <KeyRound className="h-4 w-4 text-sky-400" />
                <h3 className="text-sm font-semibold text-white">
                  AI Doorway Status
                </h3>
              </div>
              <button
                type="button"
                onClick={() => onNavigateTab("keys")}
                className="text-xs font-medium text-emerald-400 hover:text-emerald-300 cursor-pointer"
              >
                AI Keys &rarr;
              </button>
            </div>
            <p className="text-sm text-slate-300">
              <span className="text-white font-semibold">
                {data.activeMcpTokens}
              </span>{" "}
              active AI visitor pass{data.activeMcpTokens === 1 ? "" : "es"}.
            </p>
            <p className="text-xs text-slate-400 mt-2">
              {data.setup.domain &&
              data.setup.httpsActive &&
              data.setup.tlsStatus === "active" ? (
                <>
                  Protected with verified automatic HTTPS at{" "}
                  <code className="text-emerald-300">
                    https://{data.setup.domain}/mcp
                  </code>
                </>
              ) : data.setup.domain ? (
                <span className="text-amber-300">
                  HTTPS certificate for{" "}
                  <code className="text-amber-200">{data.setup.domain}</code> is{" "}
                  <strong>{data.setup.tlsStatus}</strong>
                  {data.setup.tlsError ? ` (${data.setup.tlsError})` : ""}. Keep
                  using your local SSH tunnel until DNS and HTTPS verify.
                </span>
              ) : (
                "Connect a domain in AI Keys & Settings to turn on remote HTTPS access in Caddy for Claude Code, Cursor, or Codex."
              )}
            </p>
          </div>
          <div className="flex items-center gap-2 rounded-xl border border-emerald-500/20 bg-emerald-500/5 px-3.5 py-2.5 text-xs text-emerald-300">
            <Activity className="h-4 w-4 shrink-0" />
            <span>
              Zero-Root Safety Wall active — apps never touch your server&apos;s
              Docker socket.
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
